"""Pure analysis functions: take response data, return findings. No network access here."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

# severity -> points deducted from a score of 100
PENALTY = {"high": 20, "medium": 10, "low": 5, "info": 0}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


def _h(headers: dict, name: str):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def check_hsts(headers: dict, is_https: bool) -> list[Finding]:
    if not is_https:
        return []
    v = _h(headers, "Strict-Transport-Security")
    fix = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    if not v:
        return [Finding("HSTS-MISSING", "high", "HSTS header missing",
                        "Browsers can be downgraded to HTTP (SSL stripping).", fix)]
    m = re.search(r"max-age=(\d+)", v, re.I)
    if not m or int(m.group(1)) < 15552000:  # < 180 days
        return [Finding("HSTS-WEAK", "medium", "HSTS max-age too short",
                        f"Value: {v}", fix)]
    return []


def check_csp(headers: dict) -> list[Finding]:
    v = _h(headers, "Content-Security-Policy")
    if not v:
        return [Finding("CSP-MISSING", "high", "Content-Security-Policy missing",
                        "No CSP means XSS has fewer browser-side mitigations.",
                        "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'")]
    out = []
    if re.search(r"(script-src|default-src)[^;]*'unsafe-inline'", v):
        out.append(Finding("CSP-UNSAFE-INLINE", "medium", "CSP allows 'unsafe-inline' scripts",
                           "Inline script execution weakens XSS protection.",
                           "Use nonces or hashes instead of 'unsafe-inline'."))
    if re.search(r"(script-src|default-src)[^;]*'unsafe-eval'", v):
        out.append(Finding("CSP-UNSAFE-EVAL", "medium", "CSP allows 'unsafe-eval'",
                           "eval() and similar are permitted.", "Remove 'unsafe-eval'."))
    if re.search(r"(script-src|default-src)[^;]*(\s|^)\*(\s|;|$)", v):
        out.append(Finding("CSP-WILDCARD", "medium", "CSP uses wildcard source",
                           "Scripts may load from any origin.", "List explicit trusted origins."))
    return out


def check_clickjacking(headers: dict) -> list[Finding]:
    csp = _h(headers, "Content-Security-Policy") or ""
    xfo = _h(headers, "X-Frame-Options")
    if "frame-ancestors" in csp.lower() or (xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN")):
        return []
    return [Finding("CLICKJACKING", "medium", "No clickjacking protection",
                    "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                    "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none').")]


def check_simple_headers(headers: dict) -> list[Finding]:
    out = []
    xcto = _h(headers, "X-Content-Type-Options")
    if not xcto or xcto.strip().lower() != "nosniff":
        out.append(Finding("XCTO-MISSING", "low", "X-Content-Type-Options missing",
                           "MIME sniffing is possible.", "Add: X-Content-Type-Options: nosniff"))
    if not _h(headers, "Referrer-Policy"):
        out.append(Finding("REFERRER-MISSING", "low", "Referrer-Policy missing",
                           "Full URLs may leak to other sites.",
                           "Add: Referrer-Policy: strict-origin-when-cross-origin"))
    if not _h(headers, "Permissions-Policy"):
        out.append(Finding("PERMISSIONS-MISSING", "low", "Permissions-Policy missing",
                           "Powerful browser features are not restricted.",
                           "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"))
    return out


def check_disclosure(headers: dict) -> list[Finding]:
    out = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = _h(headers, name)
        if v and re.search(r"\d+\.\d+", v):
            out.append(Finding("VERSION-DISCLOSURE", "low", f"{name} header reveals version",
                               f"{name}: {v}", f"Remove or genericise the {name} header."))
    return out


def check_cors(headers: dict) -> list[Finding]:
    origin = _h(headers, "Access-Control-Allow-Origin")
    creds = (_h(headers, "Access-Control-Allow-Credentials") or "").lower() == "true"
    if origin == "*" and creds:
        return [Finding("CORS-WILDCARD-CREDS", "high", "CORS: wildcard origin with credentials",
                        "Invalid/dangerous combination; may indicate origin reflection elsewhere.",
                        "Return a specific allow-listed origin.")]
    if origin == "*":
        return [Finding("CORS-WILDCARD", "low", "CORS allows any origin",
                        "Acceptable for public APIs only.", "Restrict to trusted origins if data is private.")]
    return []


def check_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    out = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        if is_https and "secure" not in attrs:
            out.append(Finding("COOKIE-SECURE", "medium", f"Cookie '{name}' missing Secure",
                               "Cookie may be sent over plain HTTP.", "Add the Secure attribute."))
        if "httponly" not in attrs:
            out.append(Finding("COOKIE-HTTPONLY", "medium", f"Cookie '{name}' missing HttpOnly",
                               "JavaScript (and XSS) can read this cookie.", "Add the HttpOnly attribute."))
        if not any(a.startswith("samesite") for a in attrs):
            out.append(Finding("COOKIE-SAMESITE", "low", f"Cookie '{name}' missing SameSite",
                               "Relies on browser defaults for CSRF protection.",
                               "Add SameSite=Lax (or Strict)."))
    return out


def check_https_redirect(http_status: int | None, location: str | None) -> list[Finding]:
    if http_status is None:
        return []
    if http_status in (301, 302, 307, 308) and location and location.lower().startswith("https://"):
        return []
    return [Finding("NO-HTTPS-REDIRECT", "high", "HTTP does not redirect to HTTPS",
                    f"HTTP request returned {http_status}.", "Redirect all HTTP traffic to HTTPS (301).")]


def analyze(headers: dict, set_cookies: list[str], is_https: bool,
            http_status: int | None = None, http_location: str | None = None) -> list[Finding]:
    f: list[Finding] = []
    f += check_hsts(headers, is_https)
    f += check_csp(headers)
    f += check_clickjacking(headers)
    f += check_simple_headers(headers)
    f += check_disclosure(headers)
    f += check_cors(headers)
    f += check_cookies(set_cookies, is_https)
    if is_https:
        f += check_https_redirect(http_status, http_location)
    return f


def score(findings: list[Finding]) -> tuple[int, str]:
    s = max(0, 100 - sum(PENALTY[x.severity] for x in findings))
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    return s, grade
