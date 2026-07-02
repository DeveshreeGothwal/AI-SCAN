from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "theharvester"


def run(target: str, dry_run: bool = False, mock: bool = False) -> ToolResult:
    cmd = ["theHarvester", "-d", target, "-b", "crtsh,otx,duckduckgo", "-l", "200"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=120, dry_run=dry_run, mock_output=mock_output)
