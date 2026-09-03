from __future__ import annotations

from pathlib import Path

from .base import ToolResult, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "gowitness"

_CHROME_CANDIDATES = ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"]


def _chrome_path() -> str:
    for candidate in _CHROME_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return _CHROME_CANDIDATES[0]


def run(base_url: str, screenshot_dir: Path, dry_run: bool = False, mock: bool = False,
        proxy: str | None = None) -> ToolResult:
    cmd = [
        "gowitness", "scan", "single", "-u", base_url,
        "--chrome-path", _chrome_path(), "--screenshot-path", str(screenshot_dir),
        "-T", "30", "--write-stdout",
    ]
    if proxy:
        cmd += ["--chrome-proxy", proxy]

    if mock:
        return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])
    if dry_run:
        return run_command(NAME, cmd, timeout=60, dry_run=True, proxy=proxy, proxy_flag_added=bool(proxy))

    screenshot_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(NAME, cmd, timeout=60, dry_run=False, proxy=proxy, proxy_flag_added=bool(proxy))
    if result.available and result.returncode == 0:
        shots = sorted(screenshot_dir.glob("*.jpeg")) + sorted(screenshot_dir.glob("*.jpg")) + sorted(screenshot_dir.glob("*.png"))
        if shots:
            # relative to the run directory, so it can be linked directly from summary.md
            result.extra["screenshot_path"] = f"{screenshot_dir.name}/{shots[-1].name}"
    return result
