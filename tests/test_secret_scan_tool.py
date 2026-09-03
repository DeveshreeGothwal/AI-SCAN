from unittest.mock import patch

import httpx

from reconai.tools import secret_scan_tool
from reconai.tools.base import ProxyUnavailable


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.endswith("vendor.js"):
        return httpx.Response(200, text="var cfg = {key: 'AKIAIOSFODNN7EXAMPLE'};")
    if url.endswith("clean.js"):
        return httpx.Response(200, text="console.log('hello world');")
    if url.endswith("/.env"):
        return httpx.Response(200, text="DB_PASSWORD=hunter2\nAPI_URL=https://example.com\n")
    return httpx.Response(404)


class _MockClient(httpx.Client):
    def __init__(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        super().__init__(*args, **kwargs)


def test_dry_run_does_not_make_requests():
    result = secret_scan_tool.run("https://example.com", ["https://example.com/vendor.js"], dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = secret_scan_tool.run("https://example.com", [], mock=True)
    assert result.mocked is True


def test_detects_aws_key_in_js_and_exposed_env_file():
    with patch("reconai.tools.secret_scan_tool.httpx.Client", _MockClient):
        result = secret_scan_tool.run(
            "https://example.com",
            ["https://example.com/vendor.js", "https://example.com/clean.js"],
            dry_run=False,
        )
    assert "[AWS Access Key]" in result.stdout
    assert "vendor.js" in result.stdout
    assert "[Exposed config file]" in result.stdout
    assert "/.env" in result.stdout
    assert "clean.js" not in result.stdout  # no finding for the clean file


def test_clean_target_reports_no_findings():
    with patch("reconai.tools.secret_scan_tool.httpx.Client", _MockClient), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run("https://example.com", ["https://example.com/clean.js"], dry_run=False)
    assert "No secrets or exposed config files detected" in result.stdout


# ---- opt-in validation: exactly one read-only confirmatory call per found
# Stripe/Slack secret, mirroring github_secrets_tool's use of trufflehog
# --only-verified. Off by default.

def _validation_client(handler):
    class _Client(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _Client


def test_validate_confirms_live_stripe_key():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("vendor.js"):
            return httpx.Response(200, text="const key = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ';")
        if "api.stripe.com" in url:
            return httpx.Response(200, json={"object": "list", "data": []})
        return httpx.Response(404)

    with patch("reconai.tools.secret_scan_tool.httpx.Client", _validation_client(handler)), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run(
            "https://example.com", ["https://example.com/vendor.js"], dry_run=False, validate=True,
        )
    assert "[Stripe Secret Key]" in result.stdout
    assert "VERIFIED LIVE" in result.stdout


def test_validate_reports_revoked_stripe_key():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("vendor.js"):
            return httpx.Response(200, text="const key = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ';")
        if "api.stripe.com" in url:
            return httpx.Response(401, json={"error": {"message": "Invalid API Key"}})
        return httpx.Response(404)

    with patch("reconai.tools.secret_scan_tool.httpx.Client", _validation_client(handler)), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run(
            "https://example.com", ["https://example.com/vendor.js"], dry_run=False, validate=True,
        )
    assert "invalid/revoked" in result.stdout


def test_validate_confirms_live_slack_token():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("vendor.js"):
            return httpx.Response(200, text="const t = 'xoxb-1234567890abcdefghijklmnop';")
        if "slack.com/api/auth.test" in url:
            return httpx.Response(200, json={"ok": True, "team": "Example"})
        return httpx.Response(404)

    with patch("reconai.tools.secret_scan_tool.httpx.Client", _validation_client(handler)), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run(
            "https://example.com", ["https://example.com/vendor.js"], dry_run=False, validate=True,
        )
    assert "[Slack Token]" in result.stdout
    assert "VERIFIED LIVE" in result.stdout


def test_validate_off_by_default_never_calls_the_provider():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url.endswith("vendor.js"):
            return httpx.Response(200, text="const key = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ';")
        return httpx.Response(200, json={"object": "list", "data": []})

    with patch("reconai.tools.secret_scan_tool.httpx.Client", _validation_client(handler)), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run(
            "https://example.com", ["https://example.com/vendor.js"], dry_run=False,
        )
    assert "[Stripe Secret Key]" in result.stdout
    assert "VERIFIED" not in result.stdout
    assert not any("stripe.com" in url for url in calls)


def test_validate_skips_gracefully_when_second_client_unavailable():
    # Validation is a bonus on top of the core scan -- if the proxy setup
    # can't support a second client, the scan must still complete rather
    # than crash the whole tool over the bonus feature.
    real_httpx_client = secret_scan_tool.httpx_client
    call_count = {"n": 0}

    def flaky_httpx_client(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise ProxyUnavailable("no second client available")
        return real_httpx_client(*args, **kwargs)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("vendor.js"):
            return httpx.Response(200, text="const key = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ';")
        return httpx.Response(404)

    with patch("reconai.tools.secret_scan_tool.httpx.Client", _validation_client(handler)), \
         patch("reconai.tools.secret_scan_tool.httpx_client", side_effect=flaky_httpx_client), \
         patch("reconai.tools.secret_scan_tool._CONFIG_PATHS", []):
        result = secret_scan_tool.run(
            "https://example.com", ["https://example.com/vendor.js"], dry_run=False, validate=True,
        )
    assert result.available is True
    assert "[Stripe Secret Key]" in result.stdout
    assert "VERIFIED" not in result.stdout


def test_dry_run_mentions_validation_when_enabled():
    result = secret_scan_tool.run(
        "https://example.com", ["https://example.com/vendor.js"], dry_run=True, validate=True,
    )
    assert "validate" in result.stdout.lower()
