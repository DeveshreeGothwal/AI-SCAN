from __future__ import annotations

from .base import ToolResult, run_command
from .gobuster_tool import DEFAULT_WORDLIST
from .mock_data import MOCK_OUTPUTS

NAME = "ffuf"


def run(base_url: str, dry_run: bool = False, mock: bool = False, wordlist: str = DEFAULT_WORDLIST,
        proxy: str | None = None) -> ToolResult:
    cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist, "-t", "20", "-timeout", "10", "-noninteractive", "-s"]
    if proxy:
        cmd += ["-x", proxy]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=300, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_flag_added=bool(proxy))
