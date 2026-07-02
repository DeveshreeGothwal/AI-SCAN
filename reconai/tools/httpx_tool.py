from __future__ import annotations

import tempfile
from pathlib import Path

from .base import _HTTPX_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "httpx"

_FLAGS = ["-sc", "-title", "-td", "-silent"]


def run(subdomains: list[str], dry_run: bool = False, mock: bool = False) -> ToolResult:
    """Probe discovered subdomains for live hosts using ProjectDiscovery's httpx."""
    if mock:
        cmd = [_HTTPX_BIN, "-l", "<subdomains>", *_FLAGS]
        return run_command(NAME, cmd, timeout=120, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])

    if dry_run:
        cmd = [_HTTPX_BIN, "-l", "<subdomains>", *_FLAGS]
        return run_command(NAME, cmd, timeout=120, dry_run=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        list_path = f.name
    try:
        cmd = [_HTTPX_BIN, "-l", list_path, *_FLAGS]
        return run_command(NAME, cmd, timeout=120, dry_run=False)
    finally:
        Path(list_path).unlink(missing_ok=True)
