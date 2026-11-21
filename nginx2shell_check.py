#!/usr/bin/env python3
"""
nginx2shell_check.py — passieve detectie voor "Nginx2Shell"
(CVE-2026-123007 en CVE-2026-123633)

Achtergrond
-----------
Op 18 november 2026 zijn twee kritieke kwetsbaarheden in de HTTP/2-code
van NGINX gepubliceerd (CVSS 4.0: 9.2):

  * CVE-2026-123007 ("Nginx2Shell"): integer underflow in de HTTP/2
    flow control -> out-of-bounds schrijven op de heap.
    Aanwezig sinds NGINX 1.9.5 (2015).
  * CVE-2026-123633 ("Drainbreak"): use-after-free in de HTTP/2
    connection handling. Aanwezig sinds NGINX 1.19.7 (2020).

Beide kunnen leiden tot ongeauthenticeerde remote code execution als
HTTP/2 is ingeschakeld (en bij code-executie ASLR ontbreekt of is te
omzeilen). Vaste versies: NGINX 1.30.7 (stable) en 1.31.9 (mainline);
NGINX Plus 37.3.0.1 / 37.0.8.1 cq. 37.2.0.1 / 37.0.7.1.

Dit script verzendt GEEN exploit en geen kwaadaardige HTTP/2-frames.
Het doet uitsluitend:
  1. lokaal: `nginx -V` draaien (versie + http_v2_module);
  2. op afstand: de `Server`-header lezen via een GET;
  3. op afstand: via ALPN in de TLS-handshake zien of "h2" wordt
     aangeboden (of een h2c prior-knowledge SETTINGS-frame testen).

Versie-aanduidingen van distro-packages kunnen een backport verbergen
(ook al toont de "Server"-header een ouder nummer: veel distro's
backportten de fix zonder versienummer te verhogen). Blijf altijd bij
de pakketbeheerder van het systeem zelf checken.

Gebruik
-------
  lokaal:    python3 nginx2shell_check.py --local [/pad/naar/nginx]
  op afstand: python3 nginx2shell_check.py https://example.com [https://host2 ...]
  json:      ... --json
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

C1 = "CVE-2026-123007"   # Nginx2Shell, sinds 1.9.5
C2 = "CVE-2026-123633"   # Drainbreak, sinds 1.19.7

FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)
INTRO_C1 = (1, 9, 5)
INTRO_C2 = (1, 19, 7)




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
    cve_2026_123007: str = "onbekend"
    cve_2026_123633: str = "onbekend"
    verdict: str = "onvoldoende informatie"
    notes: list[str] = field(default_factory=list)


def parse_version(text: str) -> tuple[int, ...] | None:
    """Haal een nginx-versienummer uit tekst, bv. 'nginx/1.26.2' -> (1,26,2)."""
    m = re.search(r"nginx/\s*([0-9]+(?:\.[0-9]+)+)(?:[^\d.]|$)", text)
    if m:
        return tuple(int(p) for p in m.group(1).split("."))
    return None


def is_nginx_plus(text: str) -> bool:
    m = re.search(r"nginx\s+plus\s*/?\s*v?([0-9]+(?:\.[0-9]+)*)", text, re.I)
    return bool(m) or "nginx plus" in text.lower()


def format_version(v: tuple[int, ...] | None) -> str:
    return ".".join(str(p) for p in v) if v else "onbekend"


def vulnerable_for(cve_intro: tuple[int, ...], version: tuple[int, ...]) -> bool:
    """Kwetsbaar als versie in [intro, eerste_fix_lijn) ligt.

    De gecorrigeerde releases zijn 1.30.7 (stable) en 1.31.9 (mainline);
    alles daarvoor, binnen de range sinds de introductie, is kwetsbaar.
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
    """Geef (CVE-2026-123007, CVE-2026-123633)-status terug."""
    s1 = "kwetsbaar" if vulnerable_for(INTRO_C1, version) else "niet kwetsbaar"
    s2 = "kwetsbaar" if vulnerable_for(INTRO_C2, version) else "niet kwetsbaar"
    if plus:
        # NGINX Plus-releases hebben eigen versielijnen die niet betrouwbaar
        # uit een Server-header te lezen zijn; verwijs naar de F5-adviezen.
        s1 = s2 = "onbekend (controleer de NGINX Plus-release)"
    return s1, s2


def check_local(binary: str) -> Result:
    r = Result(target=binary, mode="lokaal")
    try:
        out = subprocess.run(
            [binary, "-V"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        r.notes.append(f"`{binary} -V` faalde: {e}")
        return r

    text = (out.stderr or "") + (out.stdout or "")
    r.version, r.version_from = parse_version(text), "nginx -V"
    r.modules = re.findall(r"--with-[\w_]*http_v2_module", text)
    r.http2 = bool(r.modules or re.search(r"\bhttp_v2_module\b", text))
    plus = is_nginx_plus(text)

    if r.version is None:
        r.notes.append("Geen versienummer gevonden in `nginx -V`-uitvoer.")
        return r

    r.cve_2026_123007, r.cve_2026_123633 = check_version(r.version, plus)
    _add_caveats(r, plus)
    if plus:
        r.notes.append(
            "NGINX Plus gedetecteerd: check de exacte versie in de F5-adviezen "
            "(K000163926 / K000163928); dit script kan die niet betrouwbaar inlezen."
        )
    if not r.http2:
        r.notes.append("ngx_http_v2_module niet aangetroffen: HTTP/2 uit? "
                       "Dan zijn beide CVE's hier niet toepasbaar.")
    r.verdict = _verdict_text(r)
    return r


def _add_caveats(r: Result, plus: bool) -> None:
    if plus:
        return
    if r.cve_2026_123633 == "kwetsbaar":
        r.notes.append(
            "CVE-2026-123633 treedt enkel op als NGINX verzoeken doorstuurt "
            "naar een upstream (proxy_pass/fastcgi_pass/grpc_pass); bij "
            "louter statische bestellingen is vooral CVE-2026-123007 relevant.")
    if r.http2:
        r.notes.append(
            "ngx_http_v2_module is gecompileerd/in beeld; controleer of de "
            "configuratie HTTP/2 ook werkelijk activeert (http2 on; resp. "
            "listen ... http2 vóór 1.25.1). "
            "Versienummers in de Server-header kunnen op distro-backports "
            "wijzen die de fix zonder nummerverhoging bevatten.")


def probe_url(url: str, timeout: float, h2c: bool) -> Result:
    r = Result(target=url, mode="op afstand")
    parts = urlsplit(url if "://" in url else "https://" + url)
    scheme = (parts.scheme or "https").lower()
    if scheme not in ("https", "http"):
        r.notes.append(f"Onbekend scheme `{scheme}` in {url}; gebruik https:// of http://")
        return r
    host, tls = parts.hostname, scheme == "https"
    port = parts.port or (443 if tls else 80)
    if not host:
        r.notes.append(f"Ongeldig doel: {url}")
        return r

    # 1) Server-header uitlezen (kan uitgeschakeld zijn via server_tokens off).
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
        r.notes.append(f"Verbinden met {host}:{port} mislukte: {e}")
        return r

    head = data[:8192].decode("latin-1", "replace")
    m = re.search(r"(?im)^server:\s*(.+)$", head)
    if m:
        r.version = parse_version(m.group(1))
        r.version_from = f"Server-header van {host}:{port}"
        if r.version is None:
            r.notes.append("Server-header bevat geen bruikbaar versienummer "
                           "(server_tokens off). Gebruik --local op de host zelf.")
    else:
        r.notes.append("Geen `Server`-header: versie is hier niet uit te lezen "
                       "(server_tokens off). Gebruik --local op de host zelf.")
    if not tls:
        r.notes.append("Doel is plain HTTP; HTTP/2 over TLS kon niet getest worden.")

    # 2) HTTP/2 (h2c, cleartext prior knowledge) optioneel testen.
    if h2c and not tls:
        r.h2c_prior_knowledge = _h2c_probe(host, port, timeout)

    r.http2 = r.h2_alpn if tls else r.h2c_prior_knowledge

    if r.version is not None:
        r.cve_2026_123007, r.cve_2026_123633 = check_version(r.version, False)
        _add_caveats(r, False)
    else:
        r.notes.append("Zonder een versienummer kan de kwetsbaarheid op afstand "
                       "niet vastgesteld worden; draai --local op de server.")
    r.verdict = _verdict_text(r)
    return r


def _h2c_probe(host: str, port: int, timeout: float) -> bool | None:
    """Stuur de h2c prior-knowledge-preamble plus een leeg SETTINGS-frame
    terug en kijk of er een HTTP/2-frame terugkomt. Geen exploitinvoer."""
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
        return "onvoldoende informatie"
    unknown = (r.cve_2026_123007.startswith("onbekend")
               or r.cve_2026_123633.startswith("onbekend"))
    if r.http2 is False:
        return "veilig (HTTP/2 uit)"
    if unknown:
        return "onvoldoende informatie (controleer de versie handmatig)"
    some_vuln = "kwetsbaar" in (r.cve_2026_123007, r.cve_2026_123633)
    if some_vuln:
        return "KWETSBAAR" if r.http2 else "kwetsbaar versienummer, HTTP/2-status onbekend"
    return "versie gepatcht"


def _is_risky(r: Result) -> bool:
    return r.verdict == "KWETSBAAR" or r.verdict == "kwetsbaar versienummer, HTTP/2-status onbekend"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Passieve check voor Nginx2Shell (CVE-2026-123007 / CVE-2026-123633). "
        "Verstuurt geen exploitcode")
    ap.add_argument("targets", nargs="*", help="URL('s), bv. https://example.com")
    ap.add_argument("--local", metavar="BIN", nargs="?", const="nginx",
                    help="check lokaal met `nginx -V` (pad optioneel)")
    ap.add_argument("--timeout", type=float, default=10.0, help="time-out per probe")
    ap.add_argument("--h2c", action="store_true",
                    help="test bij plain HTTP ook h2c prior-knowledge")
    ap.add_argument("--json", action="store_true", help="uitvoer als JSON")
    args = ap.parse_args(argv)

    if not args.targets and not args.local:
        ap.error("geef ten minste een URL of --local op")

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
        print(f"  versie            : {format_version(r.version)}"
              + (f"  [via {r.version_from}]" if r.version_from else ""))
        print(f"  HTTP/2            : {r.http2 if r.http2 is not None else 'onbekend'}")
        print(f"  {C1} : {r.cve_2026_123007}")
        print(f"  {C2} : {r.cve_2026_123633}")
        print(f"  oordeel           : {r.verdict}")
        for n in r.notes:
            print(f"  notitie           : {n}")
        print()

    print(" advies: upgrade naar NGINX 1.30.7 (stable) of 1.31.9 (mainline); "
          "tijdelijke mitigatie: HTTP/2 uitschakelen, of proxy die TLS beëindigt "
          "in plaats van nginx zelf."
          if risky else
          " advies: geen Nginx2Shell-condities gevonden; herzie dit na de volgende "
          "nginx-upgrade en controleer distro-backports met de pakketbeheerder.")
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
