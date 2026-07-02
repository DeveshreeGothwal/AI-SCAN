from .base import _GETJS_BIN, ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "getjs"


def run(base_url: str, dry_run: bool = False, mock: bool = False) -> ToolResult:
    cmd = [_GETJS_BIN, "-url", base_url, "-complete"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=mock_output)
