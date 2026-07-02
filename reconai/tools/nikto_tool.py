from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "nikto"


def run(base_url: str, dry_run: bool = False, mock: bool = False) -> ToolResult:
    cmd = ["nikto", "-h", base_url, "-maxtime", "300", "-Tuning", "x", "-ask", "no"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=330, dry_run=dry_run, mock_output=mock_output)
