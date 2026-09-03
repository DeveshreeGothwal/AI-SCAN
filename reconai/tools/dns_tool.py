from __future__ import annotations

from .base import ToolResult, is_available, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "dns"

_DIG_RECORD_TYPES = ["A", "MX", "NS", "TXT"]


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    if mock:
        cmd = ["dnsrecon", "-d", target, "-t", "std"]
        return run_command(NAME, cmd, timeout=60, dry_run=dry_run, mock_output=MOCK_OUTPUTS[NAME])

    if is_available("dnsrecon"):
        cmd = ["dnsrecon", "-d", target, "-t", "std"]
        return run_command(NAME, cmd, timeout=60, dry_run=dry_run, proxy=proxy, proxy_dns=False)

    # Fallback: dnsrecon not installed, use dig for the common record types.
    if not is_available("dig"):
        cmd = ["dnsrecon", "-d", target, "-t", "std"]
        return run_command(NAME, cmd, timeout=60, dry_run=dry_run, proxy=proxy, proxy_dns=False)

    if dry_run:
        cmd = ["dig", target, "A", "+noall", "+answer"]
        return run_command(NAME, cmd, timeout=30, dry_run=True, proxy=proxy, proxy_dns=False)

    combined_stdout = []
    combined_stderr = []
    total_duration = 0.0
    last_cmd: list[str] = []
    for record_type in _DIG_RECORD_TYPES:
        cmd = ["dig", target, record_type, "+noall", "+answer"]
        last_cmd = cmd
        result = run_command(f"{NAME}-dig-{record_type}", cmd, timeout=15, dry_run=False, proxy=proxy, proxy_dns=False)
        total_duration += result.duration_s
        combined_stdout.append(f"--- {record_type} ---\n{result.stdout}")
        if result.stderr:
            combined_stderr.append(f"--- {record_type} stderr ---\n{result.stderr}")

    return ToolResult(
        tool=NAME,
        command=last_cmd,
        available=True,
        returncode=0,
        stdout="\n".join(combined_stdout),
        stderr="\n".join(combined_stderr),
        duration_s=total_duration,
        extra={"fallback": "dig"},
    )
