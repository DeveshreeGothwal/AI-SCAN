from __future__ import annotations

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "whois"


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["whois", target]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=30, dry_run=dry_run, mock_output=mock_output, proxy=proxy)
