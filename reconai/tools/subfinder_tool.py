from __future__ import annotations

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "subfinder"


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["subfinder", "-d", target, "-silent", "-timeout", "30"]
    if proxy:
        cmd += ["-proxy", proxy]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=90, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_flag_added=bool(proxy))


def parse_subdomains(stdout: str) -> list[str]:
    return [line.strip() for line in stdout.splitlines() if line.strip()]
