from unittest.mock import MagicMock, patch

import httpx

from reconai.tools import link_safety_tool
from reconai.tools.base import ToolResult


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def _no_redirect_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def _no_whois_result(*args, **kwargs) -> ToolResult:
    return ToolResult(tool="link_safety-whois", command=["whois"], available=False, returncode=None,
                       stdout="", stderr="", duration_s=0.0, skipped_reason="whois not found")


def test_dry_run_does_not_make_requests():
    result = link_safety_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = link_safety_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_flags_insecure_connection():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("http://example.com/page", dry_run=False)
    assert "[Insecure Connection]" in result.stdout


def test_flags_ip_literal_host():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://192.0.2.10/login", dry_run=False)
    assert "[IP Address Host]" in result.stdout


def test_flags_punycode_domain():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://xn--pypal-4ve.com/login", dry_run=False)
    assert "[Punycode/Homograph Domain]" in result.stdout


def test_flags_possible_brand_impersonation():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://paypal.secure-verify.example.com/login", dry_run=False)
    assert "[Possible Brand Impersonation]" in result.stdout


def test_real_brand_domain_is_not_flagged_as_impersonation():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://www.paypal.com/signin", dry_run=False)
    assert "[Possible Brand Impersonation]" not in result.stdout


def test_flags_url_shortener():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://bit.ly/abc123", dry_run=False)
    assert "[Shortened URL]" in result.stdout


def test_flags_suspicious_tld():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://free-prize.zip/claim", dry_run=False)
    assert "[Elevated-Risk TLD]" in result.stdout


def test_flags_long_redirect_chain():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        if path == "/b":
            return httpx.Response(302, headers={"location": "/c"})
        if path == "/c":
            return httpx.Response(302, headers={"location": "/d"})
        return httpx.Response(200, text="ok")

    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://example.com/a", dry_run=False)
    assert "[Long Redirect Chain]" in result.stdout


def test_flags_newly_registered_domain():
    def whois_result(*args, **kwargs) -> ToolResult:
        return ToolResult(tool="link_safety-whois", command=["whois"], available=True, returncode=0,
                           stdout="Creation Date: 2026-01-01T00:00:00Z", stderr="", duration_s=0.0)

    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=whois_result), \
         patch("reconai.tools.link_safety_tool.datetime") as mock_datetime:
        from datetime import datetime, timezone
        mock_datetime.now.return_value = datetime(2026, 1, 10, tzinfo=timezone.utc)
        mock_datetime.fromisoformat = datetime.fromisoformat
        result = link_safety_tool.run("https://example.com", dry_run=False)
    assert "[Newly Registered Domain]" in result.stdout


def test_clean_https_link_looks_safe():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("https://example.com/about", dry_run=False)
    assert "Verdict: LOOKS SAFE" in result.stdout


def test_multiple_strong_signals_produce_high_risk_verdict():
    with patch("reconai.tools.link_safety_tool.httpx.Client", _client_for(_no_redirect_handler)), \
         patch("reconai.tools.link_safety_tool.run_command", side_effect=_no_whois_result):
        result = link_safety_tool.run("http://paypal-login.xn--e1aybc.zip/verify", dry_run=False)
    assert "Verdict: HIGH RISK" in result.stdout
