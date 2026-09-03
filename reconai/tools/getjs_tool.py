from __future__ import annotations

from .base import _GETJS_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "getjs"


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = [_GETJS_BIN, "-url", base_url, "-complete"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    # getJS is one of the two binaries (with subjack) verified to honor
    # neither env-var proxying nor proxychains4 -- run_command() skips it
    # outright when a proxy is requested rather than let it leak direct
    # traffic. See base.PROXY_UNSUPPORTED_BINARIES.
    return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=mock_output, proxy=proxy)


def parse_js_urls(stdout: str) -> list[str]:
    return [line.strip() for line in stdout.splitlines() if line.strip()]
