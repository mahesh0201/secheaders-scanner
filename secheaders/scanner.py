"""Network layer: fetch a URL once (plus one HTTP probe) and run the checks."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import requests

from .checks import Finding, analyze, score

USER_AGENT = "secheaders-scanner/1.0 (passive; authorised testing only)"


def _set_cookies(resp: requests.Response) -> list[str]:
    raw = resp.raw.headers
    return raw.getlist("Set-Cookie") if hasattr(raw, "getlist") else []


def scan(url: str, timeout: float = 8.0, verify_tls: bool = True) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL must start with http:// or https://")
    is_https = parsed.scheme == "https"
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT

    resp = s.get(url, timeout=timeout, allow_redirects=False, verify=verify_tls)

    http_status = http_location = None
    if is_https:  # probe the plain-HTTP twin to see if it redirects
        http_url = urlunparse(parsed._replace(scheme="http"))
        try:
            probe = s.get(http_url, timeout=timeout, allow_redirects=False)
            http_status, http_location = probe.status_code, probe.headers.get("Location")
        except requests.RequestException:
            http_status = None  # port 80 closed: nothing to report

    findings: list[Finding] = analyze(dict(resp.headers), _set_cookies(resp), is_https,
                                      http_status, http_location)
    pts, grade = score(findings)
    return {"url": url, "status": resp.status_code, "score": pts, "grade": grade,
            "findings": [f.to_dict() for f in findings]}
