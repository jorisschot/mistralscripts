# nginx2shellcheck

A collection of small, dependency-free operational scripts. Currently contains:

- [`nginx2shell_check.py`](#nginx2shell_checkpy) — passive detection for the NGINX "Nginx2Shell" vulnerabilities (CVE-2026-123007 / CVE-2026-123633) hosted in this repository

---

## nginx2shell_check.py

A passive detector for the two critical HTTP/2 vulnerabilities in NGINX disclosed on 18 November 2026 (CVSS v4.0 9.2), collectively known as **Nginx2Shell**:

| CVE | Nickname | Bug | Present since |
|---|---|---|---|
| CVE-2026-123007 | Nginx2Shell | integer underflow in HTTP/2 flow control → heap out-of-bounds write | 1.9.5 (2015) |
| CVE-2026-123633 | Drainbreak | use-after-free in HTTP/2 connection handling | 1.19.7 (2020) |

Both can lead to unauthenticated remote code execution **if HTTP/2 is enabled** (and, for code execution, ASLR is missing or bypassable).

**This script sends no exploit data.** It reads version information, checks whether HTTP/2 is offered (ALPN in the TLS handshake / optional h2c prior-knowledge probe), and reports a verdict. Nothing crash-inducing or malicious is ever transmitted.

### Requirements

- Python 3.10+ (stdlib only — no pip dependencies)
- For the `--local` mode: access to the nginx binary on the server itself

### Usage

```bash
# Remote check (Server header + ALPN/http2 detection)
python3 nginx2shell_check.py https://example.com
python3 nginx2shell_check.py https://host1 https://host2

# Local check (most reliable — reads the real binary)
python3 nginx2shell_check.py --local /usr/sbin/nginx

# Optional: probe cleartext HTTP/2 (only useful on plain-HTTP targets)
python3 nginx2shell_check.py http://host --h2c

# Machine-readable output for monitoring
python3 nginx2shell_check.py https://host --json
```

### Options

| Flag | Description |
|---|---|
| `targets` | one or more `https://…` / `http://…` URLs |
| `--local [BIN]` | run `nginx -V` locally (defaults to `nginx` on `$PATH`) |
| `--timeout SEC` | per-probe timeout (default 10) |
| `--h2c` | also test cleartext HTTP/2 prior knowledge on plain HTTP |
| `--json` | emit results as JSON; exit code still reflects the verdict |

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | vulnerable version **and** HTTP/2 confirmed on |
| `vulnerable version number, HTTP/2 status unknown` | risky version, but HTTP/2 could not be confirmed |
| `version patched` | version is at/beyond a fixed release |
| `safe (HTTP/2 off)` | HTTP/2 not reachable — the attack surface is closed |
| `insufficient information` | version and/or HTTP/2 status could not be established (e.g. `server_tokens off`, NGINX Plus) |

### Exit codes

- `0` — no risk conditions found
- `1` — at least one target reported `VULNERABLE` or a vulnerable version with unknown HTTP/2 status (applies in both text and `--json` mode — handy for CI/cron monitoring)

### How the remote check works

1. **Server header**: reads `Server: nginx/1.31.8` from a single GET request. The header may be absent or stripped (`server_tokens off`), in which case the verdict is `insufficient information` rather than a guess.
2. **HTTP/2 detection**: negotiates TLS with ALPN (`h2`, `http/1.1`) and reports whether the server selected `h2`. On plaintext targets, `--h2c` sends the standard HTTP/2 preface plus an empty SETTINGS frame (RFC 9113, §3.4) and checks whether an HTTP/2 frame answers — a standard-conforming handshake, not an attack payload.

### Limitations — read these before trusting a verdict

- **`--local` beats remote.** Distro packages (Debian, Ubuntu, RHEL, Alpine, …) frequently backport fixes **without bumping the version number**, so the `Server` header (and sometimes `nginx -V` output) shows a vulnerable-sounding version while the actual code is fixed. Cross-check with the package manager:
  ```bash
  apt changelog nginx | head -50     # Debian / Ubuntu
  dnf updateinfo list nginx          # Fedora / RHEL
  apk info -a nginx                  # Alpine
  ```
- **Compiled module ≠ enabled.** `nginx -V` shows whether `http_v2_module` was compiled in, not whether your config enables HTTP/2 (`http2 on;`, or `listen … http2` before 1.25.1). Check `nginx.conf` for the directive.
- **NGINX Plus** follows its own release lines (R33, R37.x, …) that do not map cleanly onto OSS version numbers. The script reports `unknown` and points to the F5 advisories (K000163926 / K000163928).
- **CVE-2026-123633 needs an upstream.** It only applies when NGINX proxies to a backend (`proxy_pass`/`fastcgi_pass`/`grpc_pass`). For purely static serving, CVE-2026-123007 is the primary concern.
- A CDN or WAF that terminates TLS in front of nginx may mask the real origin server behind it.

### If the script reports a risk

1. **Upgrade** to NGINX 1.30.7 (stable) or 1.31.9 (mainline); NGINX Plus 37.3.0.1 / 37.0.8.1 (CVE-123007) or 37.2.0.1 / 37.0.7.1 (CVE-123633). Restart and confirm no old worker processes survive.
2. **Interim mitigation:** disable HTTP/2, or place a proxy that terminates TLS in front of nginx.
3. **Hunt embedded instances:** appliances, vendor boxes and container images often ship their own old nginx — that is where this class of bug lives longest.

### References

- [JFrog Security Research — Nginx2Shell: All You Need to Know](https://research.jfrog.com/post/nginx2shell-all-you-need-to-know-about-cve-2026-123007-and-cve-2026-123633/)
- [Rapid7 — CVE-2026-123007 disclosure](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)
- [nginx2shell.com — overview of both CVEs](https://nginx2shell.com/)
- F5 advisories K000163926 (CVE-2026-123007) and K000163928 (CVE-2026-123633)
