from __future__ import annotations

import tempfile
from pathlib import Path

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "sqlmap"

# Locked to detection-only: --batch (never prompts), --risk=1 --level=1 (sqlmap's
# own defaults -- the smallest, least invasive payload set, nothing that risks
# modifying data), --technique=BEU (Boolean-blind/Error-based/UNION only --
# excludes Time-based and Stacked-queries, which are slower and, for stacked
# queries, capable of running statements beyond the original query context).
# Never pass --dump/--dump-all/--os-shell/--sql-shell/--os-pwn -- those extract
# data or open a shell rather than just confirming a parameter is injectable.
_FLAGS = ["--batch", "--risk=1", "--level=1", "--technique=BEU", "--disable-coloring"]


def run(param_urls: list[str], dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    if not param_urls:
        raise ValueError("sqlmap_tool.run() requires at least one URL")

    proxy_flags = [f"--proxy={proxy}"] if proxy else []

    if mock:
        cmd = ["sqlmap", "-m", "<urls>", *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=600, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])

    if dry_run:
        cmd = ["sqlmap", "-m", "<urls>", *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=600, dry_run=True, proxy=proxy, proxy_flag_added=bool(proxy))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(param_urls))
        list_path = f.name
    try:
        cmd = ["sqlmap", "-m", list_path, *_FLAGS, *proxy_flags]
        return run_command(NAME, cmd, timeout=600, dry_run=False, proxy=proxy, proxy_flag_added=bool(proxy))
    finally:
        Path(list_path).unlink(missing_ok=True)
