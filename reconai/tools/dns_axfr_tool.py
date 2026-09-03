from __future__ import annotations

import time

from .base import ToolResult, apt_hint, is_available, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "dns_axfr"

_FAILURE_MARKERS = ("transfer failed", "connection timed out", "connection refused", "communications error")


def _parse_nameservers(dig_answer: str) -> list[str]:
    """Only lines whose record-type column is actually NS -- +short output
    for a name with a CNAME (e.g. the extremely common "www." case) mixes in
    the CNAME target too, with nothing to distinguish it from a real NS
    record; verified for real against www.banasthali.org, where `dig NS
    www.banasthali.org +short` returned "banasthali.org." (the CNAME target)
    ahead of the two real nameservers, which this tool would otherwise have
    tried (harmlessly, but wastefully and misleadingly) to AXFR against as
    if it were one of the target's own nameservers."""
    nameservers = []
    for line in dig_answer.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[3] == "NS":
            nameservers.append(fields[4].rstrip("."))
    return nameservers


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["dig", "NS", target, "+noall", "+answer"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if not is_available("dig"):
        return ToolResult(
            tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
            duration_s=0.0,
            skipped_reason=f"'dig' not found on PATH. Install with: sudo apt install {apt_hint('dig')}",
        )

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would query NS records for {target}, then attempt an AXFR zone transfer against each",
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    # proxy_dns=False: dig's own resolver init is incompatible with
    # proxychains' DNS interception (verified: "parse of /etc/resolv.conf
    # failed"); the actual zone-transfer TCP connection is still proxied
    # (verified separately), only this NS lookup falls back to the local
    # resolver.
    ns_result = run_command(NAME, cmd, timeout=15, proxy=proxy, proxy_dns=False)
    nameservers = _parse_nameservers(ns_result.stdout)

    lines = [f"$ dig NS {target} +noall +answer", ns_result.stdout.strip() or "(no output)", ""]
    if not nameservers:
        duration = time.monotonic() - start
        lines.append("no nameservers found -- cannot test zone transfer")
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout="\n".join(lines), stderr="", duration_s=duration)

    for ns in nameservers:
        axfr_cmd = ["dig", f"@{ns}", target, "AXFR"]
        axfr_result = run_command(NAME, axfr_cmd, timeout=20, proxy=proxy, proxy_dns=False)
        out = axfr_result.stdout.strip()
        lines.append(f"$ dig @{ns} {target} AXFR")
        if not out or any(marker in out.lower() for marker in _FAILURE_MARKERS):
            lines.append("no zone transfer (refused/failed) -- OK")
        else:
            lines.append(f"[CRITICAL] ZONE TRANSFER SUCCEEDED -- full DNS zone leaked by {ns}:\n{out}")
        lines.append("")

    duration = time.monotonic() - start
    return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                       stdout="\n".join(lines), stderr="", duration_s=duration)
