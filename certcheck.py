"""Check TLS certificate expiry for a list of hostnames (read-only).

Only performs a TLS handshake (no application data is sent). Uses the standard
library `ssl` and `socket` modules.

Exit codes (Nagios-style, for CI / cron / monitoring):
  0 all certificates OK     1 at least one WARN     2 at least one CRIT
  3 usage / input error
"""
import argparse
import datetime as dt
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time

OK, WARN, CRIT, USAGE = 0, 1, 2, 3
MAX_TARGETS = 100
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def parse_target(text, default_port=443):
    """'example.com', 'example.com:8443' or '[::1]:443' -> (host, port). Raises ValueError."""
    text = text.strip()
    host, port = text, default_port
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
    elif text.count(":") == 1:
        host, port = text.split(":")
    try:
        port = int(port)
    except ValueError:
        raise ValueError(f"invalid port in {text!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in {text!r}")
    ok = bool(HOST_RE.match(host))
    if not ok:
        try:
            import ipaddress
            ipaddress.ip_address(host)
            ok = True
        except ValueError:
            pass
    if not ok:
        raise ValueError(f"invalid hostname {host!r}")
    return host, port


def read_targets(path):
    targets = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if line:
                try:
                    targets.append(parse_target(line))
                except ValueError as e:
                    raise ValueError(f"{path} line {n}: {e}")
    return targets


def _decode_der(der):
    """Parse expiry info from a DER cert without verifying it (stdlib private helper)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, tmp = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(tmp)
    finally:
        os.unlink(tmp)


def fetch_cert(host, port, timeout=5.0, cafile=None):
    """Return (cert_dict, verify_error). verify_error is None when the chain+hostname verified."""
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return s.getpeercert(), None
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
    # Verification failed: reconnect without verification ONLY to read the expiry date.
    # Nothing is trusted or sent; the result is reported as an error regardless.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    return _decode_der(der), verify_error


def days_left(cert, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    return (expires - now).total_seconds() / 86400, expires


def check_target(host, port, warn_days=30, crit_days=14, timeout=5.0, cafile=None, now=None, fetch=fetch_cert):
    res = {"host": host, "port": port, "status": "OK", "days_left": None, "expires": None, "message": ""}
    try:
        cert, verify_error = fetch(host, port, timeout, cafile)
        days, expires = days_left(cert, now)
    except (OSError, ssl.SSLError, KeyError, ValueError) as e:
        res.update(status="CRIT", message=f"connection/handshake failed: {type(e).__name__}: {e}")
        return res
    res["days_left"] = round(days, 1)
    res["expires"] = expires.strftime("%Y-%m-%d %H:%M:%S UTC")
    if days < 0:
        res.update(status="CRIT", message=f"EXPIRED {abs(round(days, 1))} days ago")
    elif days <= crit_days:
        res.update(status="CRIT", message=f"expires in {round(days, 1)} days (<= {crit_days})")
    elif days <= warn_days:
        res.update(status="WARN", message=f"expires in {round(days, 1)} days (<= {warn_days})")
    else:
        res["message"] = f"expires in {round(days, 1)} days"
    if verify_error:
        res["message"] += f"; verification failed: {verify_error}"
        res["status"] = "CRIT"
    return res


def exit_code(results):
    st = {r["status"] for r in results}
    return CRIT if "CRIT" in st else WARN if "WARN" in st else OK


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Check TLS certificate expiry (handshake only, read-only).",
        epilog="Exit codes: 0 OK, 1 WARN, 2 CRIT, 3 usage error.")
    ap.add_argument("targets", nargs="*", help="host or host:port (default port 443)")
    ap.add_argument("-f", "--file", help="file with one host[:port] per line (# comments allowed)")
    ap.add_argument("--warn-days", type=int, default=30)
    ap.add_argument("--crit-days", type=int, default=14)
    ap.add_argument("--timeout", type=float, default=5.0, help="seconds per connection (default 5)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait between targets (rate limit)")
    ap.add_argument("--cafile", help="extra CA bundle (PEM) to trust, e.g. for a private CA")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.crit_days < 0 or a.warn_days < a.crit_days:
            raise ValueError("need 0 <= --crit-days <= --warn-days")
        if not 0 < a.timeout <= 60 or a.delay < 0:
            raise ValueError("--timeout must be in (0, 60] and --delay >= 0")
        targets = [parse_target(t) for t in a.targets]
        if a.file:
            targets += read_targets(a.file)
        if not targets:
            raise ValueError("no targets given (pass hostnames or --file)")
        if len(targets) > MAX_TARGETS:
            raise ValueError(f"too many targets ({len(targets)} > {MAX_TARGETS})")
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return USAGE
    results = []
    for i, (h, p) in enumerate(targets):
        if i and a.delay:
            time.sleep(a.delay)
        results.append(check_target(h, p, a.warn_days, a.crit_days, a.timeout, a.cafile))
    code = exit_code(results)
    if a.json:
        print(json.dumps({"exit_code": code, "results": results}, indent=2))
    else:
        for r in results:
            print(f"{r['status']:<4} {r['host']}:{r['port']:<5} {r['message']}")
    return code


if __name__ == "__main__":
    sys.exit(main())
