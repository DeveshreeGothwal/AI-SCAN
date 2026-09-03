from __future__ import annotations

import concurrent.futures
import time
from urllib.parse import urljoin

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "graphql_probe"

_TIMEOUT = 6.0
_WORKERS = 5
_MAX_CANDIDATES = 10
_COMMON_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/gql", "/graphiql"]
# Minimal introspection query -- reads only type names, no mutations.
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


def discover_candidates(base_url: str, *sources: str) -> list[str]:
    """Common GraphQL paths plus any graphql-looking endpoint already mentioned
    in getjs/linkfinder/waybackurls output -- reuses recon this pipeline has
    already gathered instead of crawling again."""
    candidates = [urljoin(base_url + "/", path.lstrip("/")) for path in _COMMON_PATHS]
    seen = set(candidates)
    for source in sources:
        for line in source.splitlines():
            line = line.strip()
            if "graphql" not in line.lower():
                continue
            url = line if line.startswith("http") else urljoin(base_url + "/", line.lstrip("/"))
            if url not in seen:
                seen.add(url)
                candidates.append(url)
    return candidates[:_MAX_CANDIDATES]


def _probe(client: httpx.Client, url: str) -> str | None:
    try:
        r = client.post(url, json=_INTROSPECTION_QUERY)
    except httpx.HTTPError:
        return None
    if r.status_code == 404:
        return None
    try:
        body = r.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("data"), dict) and body["data"].get("__schema"):
        return f"[GraphQL Introspection Enabled] {url} -- full schema is queryable (types, fields, mutations)"
    if "errors" in body or "data" in body:
        return f"[GraphQL Endpoint Found] {url} -- responds to GraphQL queries, introspection appears disabled"
    return None


def _format_findings(findings: list[str], num_candidates: int) -> str:
    header = f"Probed {num_candidates} candidate GraphQL endpoint(s)."
    if not findings:
        return header + "\n\nNo GraphQL endpoint found."
    return header + "\n\n" + "\n".join(findings)


def run(base_url: str, extra_sources: list[str] | None = None, dry_run: bool = False, mock: bool = False,
        proxy: str | None = None) -> ToolResult:
    candidates = discover_candidates(base_url, *(extra_sources or []))
    cmd = ["reconai-graphql-probe", f"--base-url={base_url}", f"--candidates={len(candidates)}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would send a schema-type-name introspection query to {len(candidates)} candidate GraphQL endpoint(s)",
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    findings: list[str] = []
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = [pool.submit(_probe, client, url) for url in candidates]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(candidates)),
        stderr="", duration_s=duration,
    )
