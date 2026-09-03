from __future__ import annotations

import concurrent.futures
import time

# The pip HTTP client library (see requirements.txt) -- NOT ProjectDiscovery's Go
# recon tool of the same name (that one is reconai/tools/httpx_tool.py).
import httpx

from .base import ProxyUnavailable, ToolResult, guess_org_name, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "bucket_enum"

_PREFIXES = ["", "www-", "dev-", "staging-", "backup-"]
_SUFFIXES = ["", "-backup", "-dev", "-staging", "-prod", "-assets", "-static",
             "-media", "-uploads", "-data", "-files", "-images", "-cdn", "-www"]
_TIMEOUT = 6.0
_WORKERS = 10


def _candidate_names(target: str) -> list[str]:
    base = guess_org_name(target)
    names = {f"{prefix}{base}{suffix}" for prefix in _PREFIXES for suffix in _SUFFIXES}
    return sorted(names)


def _check_s3(client: httpx.Client, name: str) -> str | None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code == 200:
        return f"[S3] {url} -- PUBLIC (listable)"
    if r.status_code == 403:
        return f"[S3] {url} -- exists, access denied (private)"
    return None


def _check_gcs(client: httpx.Client, name: str) -> str | None:
    url = f"https://storage.googleapis.com/{name}/"
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code == 200:
        return f"[GCS] {url} -- PUBLIC (listable)"
    if r.status_code == 403:
        return f"[GCS] {url} -- exists, access denied (private)"
    return None


def _check_azure(client: httpx.Client, name: str) -> str | None:
    url = f"https://{name}.blob.core.windows.net/"
    try:
        r = client.get(url)
    except httpx.ConnectError:
        return None  # DNS didn't resolve -- storage account doesn't exist
    except httpx.HTTPError:
        return None
    # any HTTP response (even 400 "no container specified") means the account exists
    return f"[Azure] {url} -- storage account exists (status {r.status_code})"


def _format_findings(findings: list[str], num_candidates: int) -> str:
    header = f"Checked {num_candidates} bucket-name candidate(s) across S3/GCS/Azure."
    if not findings:
        return header + "\n\nNo buckets/storage accounts found."
    return header + "\n\n" + "\n".join(sorted(findings))


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-bucket-enum", f"--target={target}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        candidates = _candidate_names(target)
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would check {len(candidates)} bucket-name candidate(s) across S3/GCS/Azure",
            stderr="", duration_s=0.0,
        )

    candidates = _candidate_names(target)
    start = time.monotonic()
    findings: list[str] = []
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = []
            for name in candidates:
                futures.append(pool.submit(_check_s3, client, name))
                futures.append(pool.submit(_check_gcs, client, name))
                futures.append(pool.submit(_check_azure, client, name))
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(candidates)),
        stderr="", duration_s=duration,
    )
