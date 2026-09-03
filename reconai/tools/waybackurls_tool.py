from __future__ import annotations

from .base import _WAYBACKURLS_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "waybackurls"


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    """Passively fetch historical URLs for the target from the Wayback Machine
    archive -- this queries archive.org, never the target itself."""
    cmd = [_WAYBACKURLS_BIN, target]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    # archive.org's CDX API response time varies a lot with how much history a
    # domain has -- observed 47-60s+ against a busy domain (tesla.com), so 60s
    # left no safety margin and could clip results non-deterministically.
    # waybackurls uses Go's default net/http transport, which was verified to
    # honor HTTP_PROXY/HTTPS_PROXY env vars (unlike getJS/subjack).
    return run_command(NAME, cmd, timeout=180, dry_run=dry_run, mock_output=mock_output, proxy=proxy)


def parse_param_urls(stdout: str, limit: int = 10) -> list[str]:
    """Extract unique URLs carrying query parameters, capped to bound the
    number of requests the downstream injection-testing stages will send."""
    seen: set[tuple[str, tuple[str, ...]]] = set()
    urls: list[str] = []
    for line in stdout.splitlines():
        url = line.strip()
        if not url or "?" not in url:
            continue
        base, _, query = url.partition("?")
        # same path + same param names (different values) is the same
        # injectable shape -- test it once, not once per archived value.
        param_names = tuple(sorted(p.split("=")[0] for p in query.split("&") if p))
        key = (base, param_names)
        if key in seen:
            continue
        seen.add(key)
        urls.append(url)
        if len(urls) >= limit:
            break
    return urls
