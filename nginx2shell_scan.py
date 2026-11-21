#!/usr/bin/env python3
"""
nginx2shell_scan.py -- multi-host asset scanner for "Nginx2Shell"
(CVE-2026-123007 / CVE-2026-123633).

Reads targets from a file (or positional arguments), checks them in
parallel using the same passive probes as nginx2shell_check.py, and
reports as text, CSV or SARIF 2.1.0.

A "target" is a URL or hostname; bare hostnames are treated as
https://host (add a scheme and/or :port to override). In a target file
one target goes per line; `#` comments and blank lines are ignored.

Exit codes: 0 = no risky conditions, 1 = at least one risky result
(applies in every output format).

Examples
--------
  python3 nginx2shell_scan.py -f targets.txt
  python3 nginx2shell_scan.py -f targets.txt --format csv -o report.csv
  python3 nginx2shell_scan.py -f targets.txt --format sarif -o report.sarif
  python3 nginx2shell_scan.py https://a.example https://b.example --workers 20
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import sys

from nginx2shell_check import probe_url, format_version, _is_risky

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json")

RULES = [
    {
        "id": "NGX0001",
        "name": "CVE_2026_123007",
        "shortDescription": {"text": "Nginx2Shell: integer underflow in NGINX HTTP/2 flow control"},
        "helpUri": "https://nginx2shell.com/",
        "fullDescription": {"text": (
            "NGINX OSS 1.9.5-1.31.8 with HTTP/2 enabled is affected by a heap "
            "out-of-bounds write (CVE-2026-123007) that can lead to unauthenticated "
            "remote code execution. Fixed in 1.30.7 (stable) / 1.31.9 (mainline).")},
    },
    {
        "id": "NGX0002",
        "name": "CVE_2026_123633",
        "shortDescription": {"text": "Drainbreak: use-after-free in NGINX HTTP/2 connection handling"},
        "helpUri": "https://nginx2shell.com/",
        "fullDescription": {"text": (
            "NGINX OSS 1.19.7-1.31.8 with HTTP/2 enabled and upstream proxying is "
            "affected by a use-after-free (CVE-2026-123633) that can lead to "
            "unauthenticated remote code execution. Fixed in 1.30.7 (stable) / "
            "1.31.9 (mainline).")},
    },
]

CVE_TO_RULE = {"CVE-2026-123007": "NGX0001", "CVE-2026-123633": "NGX0002"}

INFO_RULE = {
    "id": "INFO-check",
    "name": "InsufficientInformation",
    "shortDescription": {"text": "Nginx2Shell status could not be established"},
    "helpUri": "https://nginx2shell.com/",
    "fullDescription": {"text": (
        "No verdict could be reached for this target (e.g. server_tokens off "
        "or NGINX Plus); verify the version locally on the host.")},
}


def load_targets(files) -> list[str]:
    """Collect targets from files (or stdin when '-' is given), one per line."""
    targets, seen = [], set()
    for f in files:
        if f == "-":
            lines = sys.stdin.read().splitlines()
        else:
            try:
                with open(f, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
            except OSError as e:
                sys.stderr.write(f"error: cannot read {f}: {e}\n")
                continue
        for line in lines:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            t = t if "://" in t else "https://" + t
            if t not in seen:
                seen.add(t)
                targets.append(t)
    return targets


def scan(targets: list[str], timeout: float, h2c: bool, workers: int):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_url, t, timeout, h2c): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            yield fut.result()


def to_csv(results, out) -> None:
    w = csv.writer(out)
    w.writerow(["target", "version", "version_from", "http2",
                "cve_2026_123007", "cve_2026_123633", "verdict", "notes"])
    for r in results:
        w.writerow([
            r.target, format_version(r.version), r.version_from or "",
            "" if r.http2 is None else str(r.http2).lower(),
            r.cve_2026_123007, r.cve_2026_123633, r.verdict,
            " | ".join(r.notes),
        ])


def _sarif_result(r) -> list[dict]:
    affected = []
    if r.verdict == "VULNERABLE":
        affected = ["CVE-2026-123007", "CVE-2026-123633"]
    elif r.cve_2026_123007.startswith("vulnerable"):
        affected = ["CVE-2026-123007"]
        if r.cve_2026_123633.startswith("vulnerable"):
            affected.append("CVE-2026-123633")

    msg = f"{r.target}: {r.verdict}"
    if r.version is not None:
        msg += f" (nginx {format_version(r.version)})"
    for n in r.notes:
        msg += f"\n{r.target}: {n}"

    affected = affected or ["INFO-check"]
    results = []
    for cve in affected:
        rule_id = CVE_TO_RULE.get(cve, "INFO-check")
        # One SARIF result per affected rule keeps viewer mappings clean;
        # unconfirmed HTTP/2 means "possible exposure", not confirmed exploitability.
        results.append({
            "ruleId": rule_id,
            "level": "error" if rule_id != "INFO-check" and r.http2 else "note",
            "message": {"text": f"{r.target}: {cve} — {r.verdict}" if rule_id != "INFO-check" else msg},
            "properties": {
                "target": r.target,
                "version": format_version(r.version),
                "http2": r.http2,
                "cve_2026_123007": r.cve_2026_123007,
                "cve_2026_123633": r.cve_2026_123633,
            },
        })
    return results


def to_sarif(results) -> dict:
    flat = []
    for r in results:
        flat.extend(_sarif_result(r))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nginx2shellcheck",
                    "informationUri": "https://github.com/jorisschot/nginx2shellcheck",
                    "rules": RULES + [INFO_RULE],
                }
            },
            "results": flat,
        }],
    }


def write_output(payload, out_path: str | None) -> None:
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        sys.stderr.write(f"written: {out_path}\n")
    else:
        sys.stdout.write(payload)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Parallel Nginx2Shell asset scanner (passive; no exploit code)")
    ap.add_argument("targets", nargs="*", help="URL(s), e.g. https://example.com")
    ap.add_argument("-f", "--file", action="append", metavar="FILE",
                    help="target file ('-' for stdin); repeatable; # comments allowed")
    ap.add_argument("--workers", type=int, default=10, help="parallel probes (default 10)")
    ap.add_argument("--timeout", type=float, default=10.0, help="timeout per probe")
    ap.add_argument("--h2c", action="store_true",
                    help="also test h2c prior-knowledge for plain HTTP (cleartext)")
    ap.add_argument("--format", choices=("text", "csv", "sarif"), default="text")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="write report to file instead of stdout")
    args = ap.parse_args(argv)

    targets = load_targets(args.file) if args.file else []
    for t in args.targets:
        t = t if "://" in t else "https://" + t
        if t not in targets:
            targets.append(t)

    if not targets:
        ap.error("no targets: pass URLs or -f FILE (use '-' for stdin)")

    results = sorted(scan(targets, args.timeout, args.h2c, args.workers),
                     key=lambda r: r.target)
    risky = any(_is_risky(r) for r in results)

    if args.format == "csv":
        import io
        buf = io.StringIO()
        to_csv(results, buf)
        write_output(buf.getvalue(), args.output)
    elif args.format == "sarif":
        write_output(json.dumps(to_sarif(results), indent=2) + "\n", args.output)
    else:
        for r in results:
            print(f"== {r.target} ({r.mode}) ==")
            print(f"  version           : {format_version(r.version)}"
                  + (f"  [via {r.version_from}]" if r.version_from else ""))
            print(f"  HTTP/2            : {r.http2 if r.http2 is not None else 'unknown'}")
            print(f"  CVE-2026-123007   : {r.cve_2026_123007}")
            print(f"  CVE-2026-123633   : {r.cve_2026_123633}")
            print(f"  verdict           : {r.verdict}")
            for n in r.notes:
                print(f"  note              : {n}")
            print()
        if args.output:
            sys.stderr.write("note: text format ignores --output; "
                             "use --format csv or sarif for a report file\n")

    summary = (f" summary: {len(results)} target(s) checked; "
               + ("RISKY CONDITIONS FOUND" if risky else "no Nginx2Shell conditions found"))
    if args.format == "text":
        print(summary)
    else:
        sys.stderr.write(summary + "\n")
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
