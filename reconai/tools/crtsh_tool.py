from __future__ import annotations

import time

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "crtsh"

_TIMEOUT = 20.0


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    cmd = ["reconai-crtsh-query", url]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=f"[DRY-RUN] would query {url}", stderr="", duration_s=0.0)

    start = time.monotonic()
    try:
        with httpx_client(proxy=proxy, timeout=_TIMEOUT) as client:
            r = client.get(url)
            r.raise_for_status()
            records = r.json()
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    except (httpx.HTTPError, ValueError) as exc:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=1,
                           stdout="", stderr=f"crt.sh query failed: {exc}", duration_s=time.monotonic() - start)

    names: set[str] = set()
    for record in records:
        for name in record.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name:
                names.add(name)

    duration = time.monotonic() - start
    stdout = "\n".join(sorted(names)) + "\n" if names else "(no certificates found)"
    return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                       stdout=stdout, stderr="", duration_s=duration)


def parse_subdomains(stdout: str) -> list[str]:
    if stdout.strip() == "(no certificates found)":
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]
