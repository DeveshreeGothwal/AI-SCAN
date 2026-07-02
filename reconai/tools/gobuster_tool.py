from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "gobuster"

# small/medium ship with Kali by default; large needs `sudo apt install seclists`.
WORDLIST_TIERS = {
    "small": "/usr/share/wordlists/dirb/common.txt",
    "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "large": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
}
DEFAULT_WORDLIST = WORDLIST_TIERS["small"]


def run(base_url: str, dry_run: bool = False, mock: bool = False, wordlist: str = DEFAULT_WORDLIST) -> ToolResult:
    cmd = ["gobuster", "dir", "-u", base_url, "-w", wordlist, "-t", "20", "-q", "--timeout", "10s"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=300, dry_run=dry_run, mock_output=mock_output)
