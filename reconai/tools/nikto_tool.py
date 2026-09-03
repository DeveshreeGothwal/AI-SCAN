from __future__ import annotations

from urllib.parse import urlparse

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "nikto"


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["nikto", "-h", base_url, "-maxtime", "300", "-Tuning", "x", "-ask", "no"]
    # nikto's -useproxy mis-parses socks5:// URLs -- verified for real: it
    # produced "can't connect: no port given for proxy server socks5::80"
    # against a genuine Tor SOCKS5 port, i.e. it only understands an
    # http://host:port-shaped proxy. For socks4/socks5, skip the native flag
    # and fall through to run_command's proxychains4 wrapping instead
    # (confirmed working: nikto is Perl, dynamically linked against libc).
    use_native_flag = bool(proxy) and urlparse(proxy).scheme in ("http", "https")
    if use_native_flag:
        cmd += ["-useproxy", proxy]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=330, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_flag_added=use_native_flag)
