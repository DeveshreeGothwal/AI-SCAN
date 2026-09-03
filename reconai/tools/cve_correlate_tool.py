from __future__ import annotations

import os
import re
import time

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "cve_correlate"

# Bounds NVD request volume: NVD's public (unauthenticated) rate limit is 5
# requests per rolling 30s window. An optional free NVD_API_KEY (nvd.nist.gov
# signup, no cost) raises that to 50/30s, but we stay well under either.
_MAX_PAIRS = 5
_REQUEST_DELAY = 6.0

_WHATWEB_TAG_RE = re.compile(r"([A-Za-z][A-Za-z0-9_-]*)\[([^\]]+)\]")
_NMAP_LINE_RE = re.compile(r"^\d+/(?:tcp|udp)\s+open\s+\S+\s+(.+)$", re.MULTILINE)
_PRODUCT_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)\s+(\d+\.\d+(?:\.\d+)?\S*)")
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_CORE_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,2}")
_SKIP_WHATWEB_TAGS = {"Country", "IP", "Title", "UncommonHeaders"}


def _parse_whatweb(stdout: str) -> list[tuple[str, str]]:
    pairs = []
    for tag, value in _WHATWEB_TAG_RE.findall(stdout):
        if tag in _SKIP_WHATWEB_TAGS:
            continue
        version_match = _VERSION_RE.search(value)
        if not version_match:
            continue
        product = value.split("/")[0].strip() if "/" in value else tag
        pairs.append((product, version_match.group(0)))
    return pairs


def _parse_nmap(stdout: str) -> list[tuple[str, str]]:
    pairs = []
    for match in _NMAP_LINE_RE.finditer(stdout):
        pv = _PRODUCT_VERSION_RE.search(match.group(1))
        if pv:
            pairs.append((pv.group(1), pv.group(2)))
    return pairs


def _dedupe(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    result = []
    for product, version in pairs:
        key = (product.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        result.append((product, version))
    return result


def _search_version(version: str) -> str:
    """Strip build/distro-packaging suffixes before querying NVD's
    keywordSearch -- verified for real against the live API: "OpenSSH 5.3p1"
    (the literal nmap-detected version, "p1" patch-letter suffix included)
    returns 0 results, while "OpenSSH 5.3" returns 2. keywordSearch appears
    to require a fairly exact substring/phrase match against CVE
    descriptions, and descriptions essentially never spell out a patch-level
    suffix like this. The full, precise version is still shown in the
    report header -- only the search term is trimmed."""
    match = _CORE_VERSION_RE.match(version)
    return match.group(0) if match else version


def _query_nvd(product: str, version: str, proxy: str | None = None) -> list[str]:
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        with httpx_client(proxy=proxy, timeout=15.0) as client:
            r = client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": f"{product} {_search_version(version)}", "resultsPerPage": 5},
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
    except ProxyUnavailable:
        raise
    except (httpx.HTTPError, ValueError):
        return []

    lines = []
    for vuln in data.get("vulnerabilities", [])[:5]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "unknown")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        lines.append(f"{cve_id}: {desc[:150]}")
    return lines


def run(whatweb_stdout: str, nmap_stdout: str, dry_run: bool = False, mock: bool = False,
        proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-cve-correlate", "--source=whatweb+nmap"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout="[DRY-RUN] would correlate detected whatweb/nmap product versions against the NVD",
            stderr="", duration_s=0.0,
        )

    pairs = _dedupe(_parse_whatweb(whatweb_stdout) + _parse_nmap(nmap_stdout))[:_MAX_PAIRS]
    if not pairs:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout="No product/version banners detected to correlate against CVEs.",
                           stderr="", duration_s=0.0)

    start = time.monotonic()
    lines = [
        f"Correlating {len(pairs)} detected product/version pair(s) against the NVD (nvd.nist.gov).",
        "Heuristic keyword match, not a strict CPE match -- verify manually before reporting.",
        "",
    ]
    for i, (product, version) in enumerate(pairs):
        if i > 0:
            time.sleep(_REQUEST_DELAY)
        try:
            cve_lines = _query_nvd(product, version, proxy)
        except ProxyUnavailable as exc:
            return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                               duration_s=time.monotonic() - start, skipped_reason=str(exc))
        lines.append(f"### {product} {version}")
        if cve_lines:
            lines.extend(f"  - {line}" for line in cve_lines)
        else:
            lines.append("  (no CVE matches found, or the NVD query failed)")
        lines.append("")
    duration = time.monotonic() - start

    return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                       stdout="\n".join(lines), stderr="", duration_s=duration)
