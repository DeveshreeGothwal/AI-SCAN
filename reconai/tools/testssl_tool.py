from __future__ import annotations

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "testssl"


def run(target: str, port: int = 443, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["testssl", "--quiet", "--color", "0", f"{target}:{port}"]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    # testssl.sh shells out to dig internally to resolve the target -- same
    # proxy_dns incompatibility as dns_tool/dns_axfr_tool, verified for real
    # ("dig: parse of /etc/resolv.conf failed" -> "Fatal error: No IPv4/IPv6
    # address(es)"). The actual TLS handshake connection is still proxied;
    # only this internal hostname lookup falls back to the local resolver.
    return run_command(NAME, cmd, timeout=300, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_dns=False)
