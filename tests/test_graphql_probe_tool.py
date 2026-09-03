from unittest.mock import patch

import httpx

from reconai.tools import graphql_probe_tool


def test_discover_candidates_includes_common_paths_and_dedupes():
    candidates = graphql_probe_tool.discover_candidates("https://example.com")
    assert "https://example.com/graphql" in candidates
    assert "https://example.com/api/graphql" in candidates


def test_discover_candidates_picks_up_graphql_mentions_from_sources():
    linkfinder_output = "/api/v1/users\nhttps://api.example.com/graphql-internal\n"
    candidates = graphql_probe_tool.discover_candidates("https://example.com", linkfinder_output)
    assert "https://api.example.com/graphql-internal" in candidates


def test_discover_candidates_caps_total():
    many_sources = "\n".join(f"/graphql-{i}" for i in range(30))
    candidates = graphql_probe_tool.discover_candidates("https://example.com", many_sources)
    assert len(candidates) <= graphql_probe_tool._MAX_CANDIDATES


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/graphql":
        return httpx.Response(200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}})
    if request.url.path == "/api/graphql":
        return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})
    return httpx.Response(404)


def _client_for(handler):
    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return _MockClient


def test_dry_run_does_not_make_requests():
    result = graphql_probe_tool.run("https://example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_mock_returns_canned_output():
    result = graphql_probe_tool.run("https://example.com", mock=True)
    assert result.mocked is True


def test_detects_introspection_enabled_and_disabled_endpoints():
    with patch("reconai.tools.graphql_probe_tool.httpx.Client", _client_for(_handler)):
        result = graphql_probe_tool.run("https://example.com", dry_run=False)
    assert "[GraphQL Introspection Enabled]" in result.stdout
    assert "/graphql" in result.stdout
    assert "[GraphQL Endpoint Found]" in result.stdout
    assert "/api/graphql" in result.stdout


def test_no_graphql_endpoint_found():
    with patch("reconai.tools.graphql_probe_tool.httpx.Client", _client_for(lambda r: httpx.Response(404))):
        result = graphql_probe_tool.run("https://example.com", dry_run=False)
    assert "No GraphQL endpoint found" in result.stdout
