from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# ~/go/bin isn't on PATH by default, and some binary names collide with
# unrelated apt packages (e.g. apt's "httpx" is a Python HTTP client, not
# ProjectDiscovery's recon tool) -- resolve these by absolute path instead
# of trusting bare names on PATH.
GO_BIN = Path.home() / "go" / "bin"
LINKFINDER_DIR = Path.home() / "LinkFinder"
LINKFINDER_PYTHON = str(LINKFINDER_DIR / "venv" / "bin" / "python3")
LINKFINDER_SCRIPT = str(LINKFINDER_DIR / "linkfinder.py")

_HTTPX_BIN = str(GO_BIN / "httpx")
_GETJS_BIN = str(GO_BIN / "getJS")
_SUBJACK_BIN = str(GO_BIN / "subjack")

APT_HINTS = {
    "whois": "whois",
    "dig": "dnsutils",
    "dnsrecon": "dnsrecon",
    "subfinder": "subfinder (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)",
    "theHarvester": "theharvester",
    "nmap": "nmap",
    "whatweb": "whatweb",
    "nikto": "nikto",
    "gobuster": "gobuster",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
    "wafw00f": "wafw00f",
    "testssl": "testssl.sh",
    "gowitness": "gowitness",
    _HTTPX_BIN: (
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest "
        "(installs to ~/go/bin -- the apt 'httpx' package is an unrelated Python HTTP client)"
    ),
    _GETJS_BIN: "go install -v github.com/003random/getJS/v2@latest",
    _SUBJACK_BIN: "go install -v github.com/haccer/subjack@latest",
    LINKFINDER_PYTHON: (
        "git clone https://github.com/GerbenJavado/LinkFinder.git ~/LinkFinder && "
        "cd ~/LinkFinder && python3 -m venv venv && venv/bin/pip install setuptools -r requirements.txt"
    ),
}


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    available: bool
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    skipped_reason: str | None = None
    mocked: bool = False
    extra: dict = field(default_factory=dict)


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def apt_hint(binary: str) -> str:
    return APT_HINTS.get(binary, binary)


def run_command(
    tool_name: str,
    cmd: list[str],
    timeout: int = 300,
    dry_run: bool = False,
    mock_output: str | None = None,
) -> ToolResult:
    binary = cmd[0]

    if not is_available(binary):
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=False,
            returncode=None,
            stdout="",
            stderr="",
            duration_s=0.0,
            skipped_reason=(
                f"'{binary}' not found on PATH. Install with: sudo apt install {apt_hint(binary)}"
            ),
        )

    if mock_output is not None:
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=0,
            stdout=mock_output,
            stderr="",
            duration_s=0.0,
            mocked=True,
        )

    if dry_run:
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=0,
            stdout=f"[DRY-RUN] would execute: {' '.join(cmd)}",
            stderr="",
            duration_s=0.0,
        )

    start = time.monotonic()
    try:
        # Explicit stdin=DEVNULL, not just the default (inherit parent's stdin):
        # this runs inside a long-lived server's background worker thread, where
        # the parent's stdin isn't a real TTY. Some tools (e.g. subjack) use
        # os.Stdin.Stat() to decide "read targets from stdin instead of -w/-d",
        # and an inherited non-TTY stdin with nothing written to it makes them
        # silently process zero input rather than erroring -- DEVNULL is an
        # unambiguous "no stdin input" signal every tool interprets correctly.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as exc:
        # CPython quirk: even with text=True, TimeoutExpired.stdout/stderr are
        # raw bytes (decoding happens later in the normal completion path,
        # which a timeout never reaches). Left undecoded, this crashes every
        # downstream str.join() the moment any tool actually times out.
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=None,
            stdout=stdout or "",
            stderr=f"Timed out after {timeout}s",
            duration_s=time.monotonic() - start,
        )
