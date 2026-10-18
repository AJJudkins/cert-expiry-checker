import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import certcheck as c


def test_valid_cert_ok(serve):
    port, ca = serve("good", 90)
    r = c.check_target("localhost", port, cafile=ca)
    assert r["status"] == "OK" and 88 < r["days_left"] < 91


def test_warn_and_crit_thresholds(serve):
    port, ca = serve("soon", 20)
    assert c.check_target("localhost", port, 30, 14, cafile=ca)["status"] == "WARN"
    port2, ca2 = serve("verysoon", 5)
    assert c.check_target("localhost", port2, 30, 14, cafile=ca2)["status"] == "CRIT"


def test_expired_cert_reports_expiry_and_crit(serve):
    port, ca = serve("old", -10)
    r = c.check_target("localhost", port, cafile=ca)
    assert r["status"] == "CRIT" and r["days_left"] < 0 and "EXPIRED" in r["message"]


def test_untrusted_self_signed_is_crit_even_if_not_expiring(serve):
    port, _ = serve("untrusted", 90)
    r = c.check_target("localhost", port)  # system CAs do not trust it
    assert r["status"] == "CRIT" and "verification failed" in r["message"]
    assert r["days_left"] > 80  # expiry still read


def test_connection_refused_is_crit():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = c.check_target("localhost", port, timeout=1)
    assert r["status"] == "CRIT" and "failed" in r["message"]


def test_fake_clock_with_injected_fetch():
    cert = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
    import datetime as dt
    now = dt.datetime(2029, 12, 20, tzinfo=dt.timezone.utc)
    r = c.check_target("x.example", 443, 30, 14, now=now, fetch=lambda h, p, t, ca: (cert, None))
    assert r["status"] == "CRIT" and r["days_left"] == 12.0


@pytest.mark.parametrize("text,expected", [("example.com", ("example.com", 443)),
                                           ("example.com:8443", ("example.com", 8443)),
                                           ("[::1]:444", ("::1", 444)), ("127.0.0.1", ("127.0.0.1", 443))])
def test_parse_target_ok(text, expected):
    assert c.parse_target(text) == expected


@pytest.mark.parametrize("bad", ["bad host", "a.com:99999", "a.com:x", "-evil.com", "a..com", "http://a.com"])
def test_parse_target_rejects(bad):
    with pytest.raises(ValueError):
        c.parse_target(bad)


def test_cli_exit_codes_and_json(serve, tmp_path, capsys):
    good, ca_good = serve("g", 90)
    soon, ca_soon = serve("s", 20)
    assert c.main([f"localhost:{good}", "--cafile", ca_good]) == 0
    assert c.main([f"localhost:{soon}", "--cafile", ca_soon]) == 1
    capsys.readouterr()
    assert c.main([f"localhost:{soon}", "--cafile", ca_soon, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["exit_code"] == 1
    f = tmp_path / "hosts.txt"
    f.write_text(f"# comment\nlocalhost:{good}  # inline\n")
    assert c.main(["-f", str(f), "--cafile", ca_good]) == 0


def test_cli_usage_errors(tmp_path):
    assert c.main([]) == 3
    assert c.main(["bad host"]) == 3
    assert c.main(["a.com", "--warn-days", "5", "--crit-days", "10"]) == 3
    assert c.main(["-f", str(tmp_path / "missing.txt")]) == 3
    assert c.main(["a.com", "--timeout", "0"]) == 3
    assert c.main([f"h{i}.example" for i in range(101)]) == 3
