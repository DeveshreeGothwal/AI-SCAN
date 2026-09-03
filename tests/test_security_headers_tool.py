from unittest.mock import patch

import httpx

from reconai.tools import security_headers_tool


def _insecure_handler(request: httpx.Request) -> httpx.Response:
    if request.method == "OPTIONS":
        return httpx.Response(200, headers={"Allow": "GET, POST, PUT, TRACE"})
    return httpx.Response(200, headers=[
        ("Set-Cookie", "session=abc123; Path=/"),
        ("Server", "nginx/1.22.1"),
    ])


def _hardened_handler(request: httpx.Request) -> httpx.Response:
    if request.method == "OPTIONS":
        return httpx.Response(200, headers={"Allow": "GET, POST"})
    return httpx.Response(200, headers=[
        ("X-Frame-Options", "DENY"),
        ("Strict-Transport-Security", "max-age=63072000"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ])


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def test_dry_run_does_not_make_requests():
    result = security_headers_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = security_headers_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_flags_missing_headers_risky_cookie_and_risky_methods():
    with patch("reconai.tools.security_headers_tool.httpx.Client", _client_for(_insecure_handler)):
        result = security_headers_tool.run("https://example.com", dry_run=False)
    assert "[Clickjacking]" in result.stdout
    assert "[Missing Header] Strict-Transport-Security" in result.stdout
    assert "[Cookie Misconfiguration] cookie 'session' missing: secure, httponly, samesite" in result.stdout
    assert "[Information Disclosure] server header discloses a version: nginx/1.22.1" in result.stdout
    assert "[HTTP Methods]" in result.stdout
    assert "PUT" in result.stdout and "TRACE" in result.stdout


def test_hardened_target_reports_no_findings():
    with patch("reconai.tools.security_headers_tool.httpx.Client", _client_for(_hardened_handler)):
        result = security_headers_tool.run("https://example.com", dry_run=False)
    assert "No missing security headers" in result.stdout
