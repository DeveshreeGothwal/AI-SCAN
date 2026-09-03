from unittest.mock import patch

import httpx

from reconai.tools import bucket_enum_tool


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "public-bucket" in url:
        return httpx.Response(200, text="<ListBucketResult>...</ListBucketResult>")
    if "private-bucket" in url:
        return httpx.Response(403, text="<Error><Code>AccessDenied</Code></Error>")
    if "azure-account" in url and "blob.core.windows.net" in url:
        return httpx.Response(400, text="InvalidQueryParameterValue")
    raise httpx.ConnectError("nonexistent host", request=request)


class _MockClient(httpx.Client):
    def __init__(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        super().__init__(*args, **kwargs)


def test_candidate_names_derived_from_second_level_label():
    # "mark8.syfe.com" -> base name "syfe", not "mark8" or "com"
    assert "syfe" in bucket_enum_tool._candidate_names("mark8.syfe.com")


def test_candidate_names_handle_multi_part_public_suffix():
    # Regression: "www.csk.gov.in" naively guessed "gov" (the label right
    # before the TLD) instead of "csk" -- verified for real, and not just
    # noisy: it matched every unrelated "gov"-named bucket on the internet.
    names = bucket_enum_tool._candidate_names("www.csk.gov.in")
    assert "csk" in names
    assert "gov" not in names


def test_dry_run_does_not_make_requests():
    result = bucket_enum_tool.run("example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = bucket_enum_tool.run("example.com", mock=True)
    assert result.mocked is True


def test_detects_public_private_and_azure_buckets():
    with patch("reconai.tools.bucket_enum_tool.httpx.Client", _MockClient), \
         patch("reconai.tools.bucket_enum_tool._candidate_names",
               return_value=["public-bucket", "private-bucket", "azure-account", "nonexistent-xyz"]):
        result = bucket_enum_tool.run("example.com", dry_run=False)

    assert "PUBLIC" in result.stdout
    assert "public-bucket.s3.amazonaws.com" in result.stdout
    assert "storage.googleapis.com/public-bucket" in result.stdout
    assert "access denied" in result.stdout
    assert "azure-account.blob.core.windows.net" in result.stdout
    assert "storage account exists" in result.stdout
    assert "nonexistent-xyz" not in result.stdout


def test_clean_target_reports_no_findings():
    with patch("reconai.tools.bucket_enum_tool.httpx.Client", _MockClient), \
         patch("reconai.tools.bucket_enum_tool._candidate_names", return_value=["nonexistent-xyz"]):
        result = bucket_enum_tool.run("example.com", dry_run=False)
    assert "No buckets/storage accounts found" in result.stdout
