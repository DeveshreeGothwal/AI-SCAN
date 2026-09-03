from unittest.mock import patch

import httpx

from reconai.tools import privacy_scan_tool


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def test_dry_run_does_not_make_requests():
    result = privacy_scan_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = privacy_scan_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_detects_tracker_without_consent_marker():
    def handler(request):
        return httpx.Response(200, headers={"referrer-policy": "strict-origin", "permissions-policy": "geolocation=()"},
                               text="<html><head><script src='https://www.googletagmanager.com/gtm.js'></script></head></html>")
    with patch("reconai.tools.privacy_scan_tool.httpx.Client", _client_for(handler)):
        result = privacy_scan_tool.run("https://example.com", dry_run=False)
    assert "[Tracking Without Consent Signal]" in result.stdout


def test_tracker_with_consent_marker_present_is_not_flagged():
    def handler(request):
        return httpx.Response(200, headers={"referrer-policy": "strict-origin", "permissions-policy": "geolocation=()"},
                               text="<html><body><script src='https://www.googletagmanager.com/gtm.js'></script>"
                                    "<div id='cookieconsent'>We use cookies</div></body></html>")
    with patch("reconai.tools.privacy_scan_tool.httpx.Client", _client_for(handler)):
        result = privacy_scan_tool.run("https://example.com", dry_run=False)
    assert "[Tracking Without Consent Signal]" not in result.stdout


def test_detects_missing_referrer_policy_and_permissions_policy():
    def handler(request):
        return httpx.Response(200, text="<html></html>")
    with patch("reconai.tools.privacy_scan_tool.httpx.Client", _client_for(handler)):
        result = privacy_scan_tool.run("https://example.com", dry_run=False)
    assert "[Weak Referrer Policy]" in result.stdout
    assert "[Missing Permissions-Policy]" in result.stdout


def test_unsafe_url_referrer_policy_is_flagged():
    def handler(request):
        return httpx.Response(200, headers={"referrer-policy": "unsafe-url", "permissions-policy": "geolocation=()"},
                               text="<html></html>")
    with patch("reconai.tools.privacy_scan_tool.httpx.Client", _client_for(handler)):
        result = privacy_scan_tool.run("https://example.com", dry_run=False)
    assert "[Weak Referrer Policy]" in result.stdout


def test_clean_response_reports_no_findings():
    def handler(request):
        return httpx.Response(200, headers={"referrer-policy": "strict-origin", "permissions-policy": "geolocation=()"},
                               text="<html><body>hello</body></html>")
    with patch("reconai.tools.privacy_scan_tool.httpx.Client", _client_for(handler)):
        result = privacy_scan_tool.run("https://example.com", dry_run=False)
    assert "No tracking-without-consent signals" in result.stdout
