from unittest.mock import patch

import httpx

from reconai.tools import auth_audit_tool


def test_discover_candidates_includes_common_paths_and_dedupes():
    candidates = auth_audit_tool.discover_candidates("https://example.com")
    assert "https://example.com/login" in candidates
    assert "https://example.com/register" in candidates


def test_discover_candidates_picks_up_login_mentions_from_sources():
    linkfinder_output = "/api/v1/users\n/account/signin-internal\n"
    candidates = auth_audit_tool.discover_candidates("https://example.com", linkfinder_output)
    assert "https://example.com/account/signin-internal" in candidates


def test_discover_candidates_caps_total():
    many_sources = "\n".join(f"/login-{i}" for i in range(30))
    candidates = auth_audit_tool.discover_candidates("https://example.com", many_sources)
    assert len(candidates) <= auth_audit_tool._MAX_CANDIDATES


_CLEARTEXT_FORM = """
<html><body><form method="post" action="/checklogin">
<input type="text" name="user">
<input type="password" name="pass" maxlength="8">
</form></body></html>
"""

_HARDENED_FORM = """
<html><body><form method="post" action="/checklogin">
<input type="hidden" name="csrf_token" value="abc123">
<input type="text" name="user">
<input type="password" name="pass" maxlength="64">
</form></body></html>
"""

_NO_FORM_PAGE = "<html><body><h1>404 Not Found</h1></body></html>"


def _handler(body_by_path):
    def handler(request: httpx.Request) -> httpx.Response:
        body = body_by_path.get(request.url.path)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, text=body)
    return handler


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def test_dry_run_does_not_make_requests():
    result = auth_audit_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = auth_audit_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_detects_cleartext_credential_submission_and_weak_password_policy():
    handler = _handler({"/login": _CLEARTEXT_FORM})
    with patch("reconai.tools.auth_audit_tool.httpx.Client", _client_for(handler)):
        result = auth_audit_tool.run("http://example.com", dry_run=False)
    assert "[Cleartext Credential Submission]" in result.stdout
    assert "[Weak Password Policy]" in result.stdout
    assert "[Missing CSRF Protection]" in result.stdout


def test_hardened_form_over_https_with_csrf_and_long_password_is_clean():
    handler = _handler({"/login": _HARDENED_FORM})
    with patch("reconai.tools.auth_audit_tool.httpx.Client", _client_for(handler)):
        result = auth_audit_tool.run("https://example.com", dry_run=False)
    assert "[Cleartext Credential Submission]" not in result.stdout
    assert "[Weak Password Policy]" not in result.stdout
    assert "[Missing CSRF Protection]" not in result.stdout


def test_pages_without_a_password_form_are_not_scored():
    handler = _handler({"/login": _NO_FORM_PAGE})
    with patch("reconai.tools.auth_audit_tool.httpx.Client", _client_for(handler)):
        result = auth_audit_tool.run("https://example.com", dry_run=False)
    assert "No login/registration forms found" in result.stdout


def test_lockout_not_tested_note_present_when_findings_exist():
    handler = _handler({"/login": _CLEARTEXT_FORM})
    with patch("reconai.tools.auth_audit_tool.httpx.Client", _client_for(handler)):
        result = auth_audit_tool.run("http://example.com", dry_run=False)
    assert "account lockout / rate-limiting was not tested" in result.stdout
