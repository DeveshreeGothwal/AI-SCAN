from __future__ import annotations

import re

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "nmap"

# Matches lines like: "80/tcp   open  http    nginx 1.22.1"
_PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)", re.MULTILINE
)


def run(target: str, dry_run: bool = False, mock: bool = False, full_ports: bool = False,
        proxy: str | None = None) -> ToolResult:
    # -sT (TCP connect scan): a SYN scan crafts raw packets below the OS
    # socket layer, which no proxy mechanism (proxychains included) can
    # intercept -- only an explicit connect() syscall per port can be routed
    # through a proxy, and that's what -sT does.
    scan_type = ["-sT"] if proxy else []
    if full_ports:
        cmd = ["nmap", *scan_type, "-T4", "-sV", "-p-", "-Pn", target]
    else:
        cmd = ["nmap", *scan_type, "-T4", "-sV", "--top-ports", "1000", "-Pn", target]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=600, dry_run=dry_run, mock_output=mock_output, proxy=proxy)


def parse_open_web_ports(nmap_stdout: str) -> list[tuple[int, str]]:
    """Return [(port, scheme), ...] for open ports whose service looks like http(s)."""
    web_ports: list[tuple[int, str]] = []
    for match in _PORT_LINE_RE.finditer(nmap_stdout):
        service = match.group("service").lower()
        if "http" not in service:
            continue
        port = int(match.group("port"))
        scheme = "https" if "ssl" in service or port == 443 else "http"
        web_ports.append((port, scheme))
    return web_ports
