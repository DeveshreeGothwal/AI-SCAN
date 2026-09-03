from __future__ import annotations

import tempfile
from pathlib import Path

from .base import _HTTPX_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "httpx"

_FLAGS = ["-sc", "-title", "-td", "-silent"]


def run(subdomains: list[str], dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    """Probe discovered subdomains for live hosts using ProjectDiscovery's httpx."""
    proxy_flags = ["-http-proxy", proxy] if proxy else []

    if mock:
        cmd = [_HTTPX_BIN, "-l", "<subdomains>", *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=120, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])

    if dry_run:
        cmd = [_HTTPX_BIN, "-l", "<subdomains>", *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=120, dry_run=True, proxy=proxy, proxy_flag_added=bool(proxy))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        list_path = f.name
    try:
        cmd = [_HTTPX_BIN, "-l", list_path, *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=120, dry_run=False, proxy=proxy, proxy_flag_added=bool(proxy))
    finally:
        Path(list_path).unlink(missing_ok=True)
