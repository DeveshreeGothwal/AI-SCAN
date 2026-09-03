from __future__ import annotations

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "nuclei"


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["nuclei", "-u", base_url, "-silent", "-severity", "low,medium,high,critical"]
    if proxy:
        cmd += ["-proxy", proxy]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=600, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_flag_added=bool(proxy))
