from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "testssl"


def run(target: str, port: int = 443, dry_run: bool = False, mock: bool = False) -> ToolResult:
    cmd = ["testssl", "--quiet", "--color", "0", f"{target}:{port}"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=300, dry_run=dry_run, mock_output=mock_output)
