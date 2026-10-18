# Security policy

## Scope and safety
read-only TLS handshakes only (no application data); validated targets, 100-target cap, per-connection timeout and optional `--delay`. Check only hosts you own or may probe.

## What was and was not tested
**Tested (automated, in CI and locally):** expiry thresholds and exit codes against local TLS servers using self-signed certificates generated during the tests (valid, expiring, expired, untrusted); input validation; one manual run against github.com and example.com from the development container.

**Not tested:** regular use against a broad set of public or internal hosts, STARTTLS services, client-certificate servers, proxies, and Windows/macOS.

## Reporting a problem
This is a small personal portfolio project, not a supported product. If you find a security issue, please open a GitHub issue **without** secrets, credentials or real system details, or use GitHub's "Report a vulnerability" button on the Security tab if it is enabled.
