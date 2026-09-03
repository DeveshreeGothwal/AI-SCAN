from __future__ import annotations

from urllib.parse import urlparse

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "whatweb"


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["whatweb", "--color=never", "-a", "1", base_url]
    # whatweb's --proxy only speaks the HTTP CONNECT protocol -- verified for
    # real against a SOCKS5 Tor port, which replied 501 "Tor is not an HTTP
    # Proxy" (Tor itself detects and rejects HTTP CONNECT on its SOCKS port).
    # For socks4/socks5 proxies, skip the native flag entirely and fall
    # through to run_command's proxychains4 wrapping instead (confirmed
    # working: whatweb is Ruby, dynamically linked against libc).
    use_native_flag = bool(proxy) and urlparse(proxy).scheme in ("http", "https")
    if use_native_flag:
        cmd += ["--proxy", urlparse(proxy).netloc or urlparse(proxy).path]
    mock_output = MOCK_OUTPUTS[NAME] if mock else None
    return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=mock_output,
                        proxy=proxy, proxy_flag_added=use_native_flag)
