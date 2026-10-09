from __future__ import annotations

import argparse
import json
import sys

import requests

from .scanner import scan

ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
GRADES = "ABCDF"


def render(result: dict) -> str:
    lines = [f"Target: {result['url']}  (HTTP {result['status']})",
             f"Score:  {result['score']}/100  Grade: {result['grade']}", ""]
    if not result["findings"]:
        lines.append("No issues found.")
    for f in sorted(result["findings"], key=lambda x: ORDER[x["severity"]]):
        lines += [f"[{f['severity'].upper():6}] {f['title']}", f"         {f['detail']}",
                  f"         Fix: {f['fix']}", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secheaders",
                                description="Passive HTTP security header / cookie scanner.")
    p.add_argument("url")
    p.add_argument("--i-have-permission", action="store_true", required=True,
                   help="Confirm you own the target or have written permission to test it")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--fail-under", choices=list(GRADES), help="Exit 1 if grade is worse than this")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    args = p.parse_args(argv)

    try:
        result = scan(args.url, verify_tls=not args.insecure)
    except (ValueError, requests.RequestException) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, indent=2) if args.json else render(result))
    if args.fail_under and GRADES.index(result["grade"]) > GRADES.index(args.fail_under):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
