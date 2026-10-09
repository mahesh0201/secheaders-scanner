# secheaders - HTTP Security Header Scanner

A small, **passive** command-line scanner that makes one request to a website you own (plus one HTTP probe)
and reports missing or weak browser-side security controls. Each finding has a severity and a concrete fix,
and the site gets a 0-100 score and an A-F grade.

> **Authorised use only.** Run it against sites you own or have written permission to test.
> The CLI refuses to run without the `--i-have-permission` flag. It sends no attack payloads.

## What it checks

| Check | Why it matters (OWASP reference) |
|-------|----------------------------------|
| `Strict-Transport-Security` presence and max-age | Prevents SSL stripping / downgrade (A02 Cryptographic Failures) |
| `Content-Security-Policy` presence, `unsafe-inline`, `unsafe-eval`, wildcards | Mitigates XSS impact (A03 Injection) |
| Clickjacking: `X-Frame-Options` or CSP `frame-ancestors` | UI redress attacks |
| `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | Hardening and privacy |
| `Server` / `X-Powered-By` version disclosure | Fingerprinting (A05 Security Misconfiguration) |
| CORS wildcard, wildcard + credentials | Cross-origin data exposure |
| Cookie flags: `Secure`, `HttpOnly`, `SameSite` | Session theft and CSRF (A07 Authentication Failures) |
| HTTP -> HTTPS redirect | Plain-text exposure |

## Install and run

```bash
git clone https://github.com/mahesh0201/secheaders-scanner.git
cd secheaders-scanner
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m secheaders https://your-own-site.example --i-have-permission
python -m secheaders https://your-own-site.example --i-have-permission --json
python -m secheaders https://your-own-site.example --i-have-permission --fail-under B   # exit 1 if worse than B
```

Example output:

```
Target: https://your-own-site.example  (HTTP 200)
Score:  55/100  Grade: D

[HIGH  ] Content-Security-Policy missing
         No CSP means XSS has fewer browser-side mitigations.
         Fix: Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
[MEDIUM] Cookie 'sid' missing HttpOnly
...
```

`--fail-under` makes it usable as a **CI gate** for your own deployments.

## Architecture

```
secheaders/checks.py    pure functions: headers in -> findings out (easy to unit test, no network)
secheaders/scanner.py   network layer (requests); redirects are NOT followed so they can be inspected
secheaders/cli.py       argparse CLI, text/JSON output, exit codes
tests/                  pytest, including a live test against a throwaway local HTTP server
```

Scoring: start at 100, subtract 20 / 10 / 5 per high / medium / low finding.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Limitations

- Header-level checks only: it does not find application vulnerabilities (SQLi, XSS, auth flaws).
- Only inspects the single URL given, not every page or API route.
- A policy being *present* does not prove it is *correct*; review CSP manually.

## Ideas to extend

- TLS certificate expiry and protocol checks
- Crawl a sitemap and scan multiple pages
- SARIF output for GitHub code scanning
- Compare two scans over time

## License

MIT
