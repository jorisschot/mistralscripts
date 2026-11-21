#!/usr/bin/env python3
"""
nginx2shell_check.py -- passive detection for "Nginx2Shell"
(CVE-2026-123007 and CVE-2026-123633)

Background
-----------
On 18 November 2026 two critical vulnerabilities in the HTTP/2 code of
NGINX were disclosed (CVSS 4.0: 9.2):

  * CVE-2026-123007 ("Nginx2Shell"): integer underflow in HTTP/2
    flow control -> out-of-bounds write on the heap.
    Present since NGINX 1.9.5 (2015).
  * CVE-2026-123633 ("Drainbreak"): use-after-free in HTTP/2
    connection handling. Present since NGINX 1.19.7 (2020).

Both can lead to unauthenticated remote code execution when HTTP/2 is
enabled (and, for code execution, ASLR is absent or can be bypassed).
Fixed versions: NGINX 1.30.7 (stable) and 1.31.9 (mainline); NGINX Plus
versions 37.3.0.1 / 37.0.8.1 respectively 37.2.0.1 / 37.0.7.1.

This script sends NO exploit and NO malicious HTTP/2 frames. It only:
  1. locally: run `nginx -V` (version + http_v2_module);
  2. remotely: read the `Server` header via a GET;
  3. remotely: check via ALPN in the TLS handshake whether "h2" is
     offered (or test an h2c prior-knowledge SETTINGS frame).

Distro package versions may hide a backport (even when the "Server"
header shows an older number: many distros backported the fix without
bumping the version). Always cross-check with the package manager on
the system itself.

Usage
-------
  local:      python3 nginx2shell_check.py --local [/path/to/nginx]
  remote:     python3 nginx2shell_check.py https://example.com [https://host2 ...]
  json:       ... --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit

C1 = "CVE-2026-123007"   # Nginx2Shell, since 1.9.5
C2 = "CVE-2026-123633"   # Drainbreak, since 1.19.7

FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)
INTRO_C1 = (1, 9, 5)
INTRO_C2 = (1, 19, 7)

UNKNOWN = "unknown"
VULNERABLE = "vulnerable"
NOT_VULNERABLE = "not vulnerable"


@dataclass
class Result:
    target: str
    mode: str
    version: tuple[int, ...] | None = None
    version_from: str | None = None
    http2: bool | None = None
    h2_alpn: bool | None = None
    h2c_prior_knowledge: bool | None = None
    modules: list[str] = field(default_factory=list)
    cve_2026_123007: str = UNKNOWN
    cve_2026_123633: str = UNKNOWN
    verdict: str = "insufficient information"
    notes: list[str] = field(default_factory=list)


def parse_version(text: str) -> tuple[int, ...] | None:
    """Extract an nginx version number from text, e.g. 'nginx/1.26.2' -> (1,26,2)."""
    m = re.search(r"nginx/\s*([0-9]+(?:\.[0-9]+)+)(?:[^\d.]|$)", text)
    if m:
        return tuple(int(p) for p in m.group(1).split("."))
    return None


def is_nginx_plus(text: str) -> bool:
    m = re.search(r"nginx\s+plus\s*/?\s*v?([0-9]+(?:\.[0-9]+)*)", text, re.I)
    return bool(m) or "nginx plus" in text.lower()


def format_version(v: tuple[int, ...] | None) -> str:
    return ".".join(str(p) for p in v) if v else "unknown"


def vulnerable_for(cve_intro: tuple[int, ...], version: tuple[int, ...]) -> bool:
    """Vulnerable if the version lies in [intro, first_fix_line).

    The corrected releases are 1.30.7 (stable) and 1.31.9 (mainline);
    everything before that, within the range since introduction, is
    vulnerable.
    """
    if version < cve_intro:
        return False
    if version[:2] <= (1, 29):
        return True
    if version[:2] == (1, 30):
        return version < FIXED_STABLE
    if version[:2] >= (1, 31):
        return version < FIXED_MAINLINE
    return True


def check_version(version: tuple[int, ...], plus: bool) -> tuple[str, str]:
    """Return (CVE-2026-123007, CVE-2026-123633) status."""
    s1 = VULNERABLE if vulnerable_for(INTRO_C1, version) else NOT_VULNERABLE
    s2 = VULNERABLE if vulnerable_for(INTRO_C2, version) else NOT_VULNERABLE
    if plus:
        # NGINX Plus releases follow their own version lines that cannot
        # be reliably read from a Server header; refer to the F5 advisories.
        s1 = s2 = "unknown (check the NGINX Plus release)"
    return s1, s2


def check_local(binary: str) -> Result:
    r = Result(target=binary, mode="local")
    try:
        out = subprocess.run(
            [binary, "-V"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        r.notes.append(f"`{binary} -V` failed: {e}")
        return r

    text = (out.stderr or "") + (out.stdout or "")
    r.version, r.version_from = parse_version(text), "nginx -V"
    r.modules = re.findall(r"--with-[\w_]*http_v2_module", text)
    r.http2 = bool(r.modules or re.search(r"\bhttp_v2_module\b", text))
    plus = is_nginx_plus(text)

    if r.version is None:
        r.notes.append("No version number found in `nginx -V` output.")
        return r

    r.cve_2026_123007, r.cve_2026_123633 = check_version(r.version, plus)
    _add_caveats(r, plus)
    if plus:
        r.notes.append(
            "NGINX Plus detected: check the exact version in the F5 advisories "
            "(K000163926 / K000163928); this script cannot read those reliably."
        )
    if not r.http2:
        r.notes.append("ngx_http_v2_module not found: HTTP/2 off? "
                       "Then both CVEs are not applicable here.")
    r.verdict = _verdict_text(r)
    return r


def _add_caveats(r: Result, plus: bool) -> None:
    if plus:
        return
    if r.cve_2026_123633 == VULNERABLE:
        r.notes.append(
            "CVE-2026-123633 only triggers if NGINX forwards requests "
            "to an upstream (proxy_pass/fastcgi_pass/grpc_pass); for "
            "purely static files, CVE-2026-123007 is the main concern.")
    if r.http2:
        r.notes.append(
            "ngx_http_v2_module is compiled/present; verify that the "
            "configuration actually enables HTTP/2 (http2 on; or "
            "listen ... http2 before 1.25.1). "
            "Version numbers in the Server header may point to distro "
            "backports containing the fix without a version bump.")


def probe_url(url: str, timeout: float, h2c: bool) -> Result:
    r = Result(target=url, mode="remote")
    parts = urlsplit(url if "://" in url else "https://" + url)
    scheme = (parts.scheme or "https").lower()
    if scheme not in ("https", "http"):
        r.notes.append(f"Unknown scheme `{scheme}` in {url}; use https:// or http://")
        return r
    host, tls = parts.hostname, scheme == "https"
    port = parts.port or (443 if tls else 80)
    if not host:
        r.notes.append(f"Invalid target: {url}")
        return r

    # 1) Read the Server header (may be disabled via server_tokens off).
    try:
        ctx = ssl.create_default_context()
        if tls:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=timeout) as raw:
            if tls:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    proto = s.selected_alpn_protocol()
                    r.h2_alpn = proto == "h2"
                    s.sendall(
                        f"GET {parts.path or '/'} HTTP/1.1\r\n"
                        f"Host: {host}\r\nUser-Agent: nginx2shell-check/1.0\r\n"
                        f"Connection: close\r\n\r\n".encode()
                    )
                    data = _recv_all(s, timeout)
            else:
                r.h2_alpn = None
                raw.sendall(
                    f"GET {parts.path or '/'} HTTP/1.1\r\n"
                    f"Host: {host}\r\nUser-Agent: nginx2shell-check/1.0\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
                data = _recv_all(raw, timeout)
    except (OSError, ssl.SSLError, socket.timeout) as e:
        r.notes.append(f"Connecting to {host}:{port} failed: {e}")
        return r

    head = data[:8192].decode("latin-1", "replace")
    m = re.search(r"(?im)^server:\s*(.+)$", head)
    if m:
        r.version = parse_version(m.group(1))
        r.version_from = f"Server header of {host}:{port}"
        if r.version is None:
            r.notes.append("Server header contains no usable version number "
                           "(server_tokens off). Use --local on the host itself.")
    else:
        r.notes.append("No `Server` header: version cannot be read here "
                       "(server_tokens off). Use --local on the host itself.")
    if not tls:
        r.notes.append("Target is plain HTTP; HTTP/2 over TLS could not be tested.")

    # 2) Optionally test HTTP/2 (h2c, cleartext prior knowledge).
    if h2c and not tls:
        r.h2c_prior_knowledge = _h2c_probe(host, port, timeout)

    r.http2 = r.h2_alpn if tls else r.h2c_prior_knowledge

    if r.version is not None:
        r.cve_2026_123007, r.cve_2026_123633 = check_version(r.version, False)
        _add_caveats(r, False)
    else:
        r.notes.append("Without a version number the vulnerability cannot be "
                       "assessed remotely; run --local on the server.")
    r.verdict = _verdict_text(r)
    return r


def _h2c_probe(host: str, port: int, timeout: float) -> bool | None:
    """Send the h2c prior-knowledge preamble plus an empty SETTINGS frame
    back and check whether an HTTP/2 frame returns. No exploit input."""
    preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(preamble + settings)
            resp = _recv_all(s, timeout, limit=2048)
    except OSError:
        return None
    if resp.startswith(b"HTTP"):
        return False
    if len(resp) >= 9 and resp[3] in (0x03, 0x04, 0x06, 0x07):
        return True
    return None


def _recv_all(stream, timeout: float, limit: int = 65536) -> bytes:
    stream.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < limit:
            chunk = stream.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks)


def _verdict_text(r: Result) -> str:
    if r.version is None:
        return "insufficient information"
    unknown = (r.cve_2026_123007.startswith(UNKNOWN)
               or r.cve_2026_123633.startswith(UNKNOWN))
    if r.http2 is False:
        return "safe (HTTP/2 off)"
    if unknown:
        return "insufficient information (check the version manually)"
    some_vuln = VULNERABLE in (r.cve_2026_123007, r.cve_2026_123633)
    if some_vuln:
        return "VULNERABLE" if r.http2 else "vulnerable version number, HTTP/2 status unknown"
    return "version patched"


def _is_risky(r: Result) -> bool:
    return r.verdict == "VULNERABLE" or r.verdict == "vulnerable version number, HTTP/2 status unknown"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Passive check for Nginx2Shell (CVE-2026-123007 / CVE-2026-123633). "
        "Sends no exploit code")
    ap.add_argument("targets", nargs="*", help="URL(s), e.g. https://example.com")
    ap.add_argument("--local", metavar="BIN", nargs="?", const="nginx",
                    help="check locally with `nginx -V` (path optional)")
    ap.add_argument("--timeout", type=float, default=10.0, help="timeout per probe")
    ap.add_argument("--h2c", action="store_true",
                    help="also test h2c prior-knowledge for plain HTTP (cleartext)")
    ap.add_argument("--json", action="store_true", help="output as JSON")
    args = ap.parse_args(argv)

    if not args.targets and not args.local:
        ap.error("provide at least a URL or --local")

    results = []
    if args.local:
        results.append(check_local(args.local))
    for t in args.targets:
        results.append(probe_url(t, args.timeout, args.h2c))

    risky = any(_is_risky(r) for r in results)

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
        return 1 if risky else 0

    for r in results:
        print(f"== {r.target} ({r.mode}) ==")
        print(f"  version           : {format_version(r.version)}"
              + (f"  [via {r.version_from}]" if r.version_from else ""))
        print(f"  HTTP/2            : {r.http2 if r.http2 is not None else 'unknown'}")
        print(f"  {C1} : {r.cve_2026_123007}")
        print(f"  {C2} : {r.cve_2026_123633}")
        print(f"  verdict           : {r.verdict}")
        for n in r.notes:
            print(f"  note              : {n}")
        print()

    print(" advice: upgrade to NGINX 1.30.7 (stable) or 1.31.9 (mainline); "
          "interim mitigation: disable HTTP/2, or use a proxy that terminates "
          "TLS instead of nginx itself."
          if risky else
          " advice: no Nginx2Shell conditions found; revisit after the next "
          "nginx upgrade and check distro backports with the package manager.")
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
