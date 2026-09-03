from __future__ import annotations

import concurrent.futures
import time
from urllib.parse import urlparse

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "cors_scan"

_TIMEOUT = 6.0
_WORKERS = 4


def _origin_variants(base_url: str) -> list[str]:
    # Covers the CORS misconfiguration patterns that recur across bug bounty
    # writeups: naive reflection of any Origin, accepting the literal string
    # "null" (sent by sandboxed iframes and some browser contexts), and
    # substring/regex validation bypassed by a domain that merely starts or
    # ends with the real hostname.
    host = urlparse(base_url).hostname or ""
    return [
        "https://reconai-cors-test.invalid",
        "null",
        f"https://evil-{host}",
        f"https://{host}.reconai-cors-test.invalid",
    ]


def _check_origin(client: httpx.Client, base_url: str, origin: str) -> str | None:
    try:
        r = client.get(base_url, headers={"Origin": origin})
    except httpx.HTTPError:
        return None
    acao = r.headers.get("access-control-allow-origin")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao is None:
        return None
    if acao == "*":
        if acac:
            return ("[CORS Misconfiguration] server sends Access-Control-Allow-Origin: * "
                    "together with Access-Control-Allow-Credentials: true -- invalid per spec, "
                    "but some stacks honor it, which would let any site read authenticated responses")
        return None
    if acao == origin:
        credential_note = " -- credentials also allowed, so session-riding is possible" if acac else ""
        return f"[CORS Misconfiguration] Origin '{origin}' reflected verbatim in Access-Control-Allow-Origin{credential_note}"
    return None


def _format_findings(findings: list[str], num_variants: int) -> str:
    header = f"Tested {num_variants} Origin header variant(s) against the base URL."
    if not findings:
        return header + "\n\nNo CORS misconfiguration detected."
    return header + "\n\n" + "\n".join(findings)


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    variants = _origin_variants(base_url)
    cmd = ["reconai-cors-scan", f"--base-url={base_url}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would test {len(variants)} Origin header variant(s) against {base_url}",
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    findings: list[str] = []
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = [pool.submit(_check_origin, client, base_url, origin) for origin in variants]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
    duration = time.monotonic() - start

    # dict.fromkeys dedupes while preserving order -- a server that reflects
    # every Origin unconditionally would otherwise produce the same wildcard
    # finding once per variant tested.
    findings = list(dict.fromkeys(findings))

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(variants)),
        stderr="", duration_s=duration,
    )
