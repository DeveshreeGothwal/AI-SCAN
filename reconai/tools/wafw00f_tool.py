from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "wafw00f"


def run(base_url: str, dry_run: bool = False, mock: bool = False) -> ToolResult:
    cmd = ["wafw00f", base_url]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=mock_output)
