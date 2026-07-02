from __future__ import annotations

import re
import tempfile
from pathlib import Path

from .base import _SUBJACK_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "subjack"

# -a: also check subdomains with no identified CNAME (subjack's own README calls
# this "recommended" -- without it, takeovers on unusual/undetected CNAME targets
# are silently missed).
_FLAGS = ["-t", "100", "-timeout", "30", "-ssl", "-a", "-v"]

# subjack prints ANSI color codes unconditionally -- it never checks whether
# stdout is a terminal, so captured output is full of raw escape sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def run(subdomains: list[str], dry_run: bool = False, mock: bool = False) -> ToolResult:
    """Check discovered subdomains for takeover-able dangling CNAMEs using subjack."""
    if mock:
        cmd = [_SUBJACK_BIN, "-w", "<subdomains>", *_FLAGS]
        return run_command(NAME, cmd, timeout=120, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])

    if dry_run:
        cmd = [_SUBJACK_BIN, "-w", "<subdomains>", *_FLAGS]
        return run_command(NAME, cmd, timeout=120, dry_run=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        list_path = f.name
    try:
        cmd = [_SUBJACK_BIN, "-w", list_path, *_FLAGS]
        result = run_command(NAME, cmd, timeout=120, dry_run=False)
        result.stdout = _strip_ansi(result.stdout)
        result.stderr = _strip_ansi(result.stderr)
        return result
    finally:
        Path(list_path).unlink(missing_ok=True)
