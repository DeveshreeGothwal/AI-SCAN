from unittest.mock import patch

import httpx

from reconai.tools import cors_scan_tool


def _reflecting_handler(request: httpx.Request) -> httpx.Response:
    origin = request.headers.get("origin", "")
    if origin == "https://reconai-cors-test.invalid":
        return httpx.Response(200, headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        })
    return httpx.Response(200)


def _wildcard_with_credentials_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })


def _safe_wildcard_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def test_dry_run_does_not_make_requests():
    result = cors_scan_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = cors_scan_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_detects_reflected_origin_with_credentials():
    with patch("reconai.tools.cors_scan_tool.httpx.Client", _client_for(_reflecting_handler)):
        result = cors_scan_tool.run("https://example.com", dry_run=False)
    assert "[CORS Misconfiguration]" in result.stdout
    assert "reconai-cors-test.invalid" in result.stdout
    assert "session-riding" in result.stdout


def test_detects_wildcard_with_credentials():
    with patch("reconai.tools.cors_scan_tool.httpx.Client", _client_for(_wildcard_with_credentials_handler)):
        result = cors_scan_tool.run("https://example.com", dry_run=False)
    assert "[CORS Misconfiguration]" in result.stdout
    findings = [line for line in result.stdout.splitlines() if line.startswith("[CORS")]
    assert len(findings) == 1  # deduped across the 4 origin variants tested


def test_plain_wildcard_without_credentials_is_not_flagged():
    with patch("reconai.tools.cors_scan_tool.httpx.Client", _client_for(_safe_wildcard_handler)):
        result = cors_scan_tool.run("https://example.com", dry_run=False)
    assert "No CORS misconfiguration detected" in result.stdout
