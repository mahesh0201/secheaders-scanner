import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from secheaders import checks
from secheaders.cli import main
from secheaders.scanner import scan

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def ids(findings):
    return {f.id for f in findings}


def test_good_headers_score_a():
    f = checks.analyze(GOOD, [], True, 301, "https://x/")
    assert f == [] and checks.score(f) == (100, "A")


def test_missing_everything_is_bad():
    f = checks.analyze({}, [], True, 200, None)
    assert {"HSTS-MISSING", "CSP-MISSING", "CLICKJACKING", "NO-HTTPS-REDIRECT"} <= ids(f)
    assert checks.score(f)[1] in ("D", "F")


def test_hsts_not_checked_on_http():
    assert checks.check_hsts({}, is_https=False) == []


def test_hsts_short_max_age():
    assert ids(checks.check_hsts({"strict-transport-security": "max-age=60"}, True)) == {"HSTS-WEAK"}


def test_header_names_case_insensitive():
    assert checks.check_hsts({"STRICT-TRANSPORT-SECURITY": "max-age=31536000"}, True) == []


def test_csp_unsafe_inline_and_eval():
    h = {"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'"}
    assert {"CSP-UNSAFE-INLINE", "CSP-UNSAFE-EVAL"} <= ids(checks.check_csp(h))


def test_csp_wildcard():
    assert "CSP-WILDCARD" in ids(checks.check_csp({"Content-Security-Policy": "default-src *"}))


def test_xfo_counts_as_clickjacking_protection():
    assert checks.check_clickjacking({"X-Frame-Options": "DENY"}) == []


def test_version_disclosure():
    assert ids(checks.check_disclosure({"Server": "Apache/2.4.49"})) == {"VERSION-DISCLOSURE"}
    assert checks.check_disclosure({"Server": "nginx"}) == []


def test_cors_wildcard_with_credentials():
    h = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    assert ids(checks.check_cors(h)) == {"CORS-WILDCARD-CREDS"}


def test_cookie_flags():
    assert checks.check_cookies(["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"], True) == []
    bad = ids(checks.check_cookies(["sid=1; Path=/"], True))
    assert bad == {"COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"}


def test_https_redirect():
    assert checks.check_https_redirect(301, "https://example.com/") == []
    assert ids(checks.check_https_redirect(200, None)) == {"NO-HTTPS-REDIRECT"}


# ---- integration test against a local throwaway server --------------------
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.send_header("Set-Cookie", "pref=1; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


def test_live_scan_detects_issues(server):
    r = scan(server)
    found = {f["id"] for f in r["findings"]}
    assert {"CSP-MISSING", "VERSION-DISCLOSURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"} <= found
    assert r["grade"] in ("D", "F", "C")


def test_cli_requires_permission_flag(server):
    with pytest.raises(SystemExit):
        main([server])


def test_cli_fail_under(server, capsys):
    assert main([server, "--i-have-permission", "--fail-under", "B"]) == 1
    assert "Grade" in capsys.readouterr().out


def test_invalid_url_rejected():
    with pytest.raises(ValueError):
        scan("ftp://example.com")
