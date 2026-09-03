from __future__ import annotations

from .base import LINKFINDER_PYTHON, LINKFINDER_SCRIPT, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "linkfinder"


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = [LINKFINDER_PYTHON, LINKFINDER_SCRIPT, "-i", base_url, "-o", "cli"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=mock_output, proxy=proxy)
