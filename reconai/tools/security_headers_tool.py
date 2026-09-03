from __future__ import annotations

import re
import time
from urllib.parse import urlparse

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "security_headers"

_TIMEOUT = 8.0
_RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")
_VERSION_RE = re.compile(r"/\d")


def _clickjacking_finding(headers: httpx.Headers) -> list[str]:
    csp = headers.get("content-security-policy", "")
    if headers.get("x-frame-options") is None and "frame-ancestors" not in csp.lower():
        return ["[Clickjacking] no X-Frame-Options header and no CSP frame-ancestors "
                "directive -- the page can be embedded in a hostile <iframe>"]
    return []


def _cookie_findings(headers: httpx.Headers) -> list[str]:
    findings = []
    for name, value in headers.multi_items():
        if name.lower() != "set-cookie":
            continue
        cookie_name = value.split("=", 1)[0].strip()
        lowered = value.lower()
        missing = [flag for flag in ("secure", "httponly") if flag not in lowered]
        if "samesite" not in lowered:
            missing.append("samesite")
        if missing:
            findings.append(f"[Cookie Misconfiguration] cookie '{cookie_name}' missing: {', '.join(missing)}")
    return findings


def _header_findings(base_url: str, headers: httpx.Headers) -> list[str]:
    findings = _clickjacking_finding(headers)

    if urlparse(base_url).scheme == "https" and headers.get("strict-transport-security") is None:
        findings.append("[Missing Header] Strict-Transport-Security (HSTS) not set on an HTTPS response")

    if (headers.get("x-content-type-options") or "").lower() != "nosniff":
        findings.append("[Missing Header] X-Content-Type-Options: nosniff not set -- browsers may MIME-sniff responses")

    if headers.get("content-security-policy") is None:
        findings.append("[Missing Header] no Content-Security-Policy set")

    for header_name in ("server", "x-powered-by"):
        value = headers.get(header_name)
        if value and _VERSION_RE.search(value):
            findings.append(f"[Information Disclosure] {header_name} header discloses a version: {value}")

    findings.extend(_cookie_findings(headers))
    return findings


def _method_findings(client: httpx.Client, base_url: str) -> list[str]:
    try:
        r = client.options(base_url)
    except httpx.HTTPError:
        return []
    allowed = {m.strip().upper() for m in r.headers.get("allow", "").split(",") if m.strip()}
    risky = allowed & set(_RISKY_METHODS)
    if risky:
        return [f"[HTTP Methods] potentially risky method(s) enabled: {', '.join(sorted(risky))}"]
    return []


def _format_findings(findings: list[str]) -> str:
    if not findings:
        return "No missing security headers, risky cookies, or risky HTTP methods detected."
    return "\n".join(findings)


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-security-headers", f"--base-url={base_url}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would audit security headers, cookie flags, and HTTP methods on {base_url}",
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        try:
            r = client.get(base_url)
        except httpx.HTTPError as exc:
            return ToolResult(tool=NAME, command=cmd, available=True, returncode=1,
                               stdout="", stderr=str(exc), duration_s=time.monotonic() - start)
        findings = _header_findings(base_url, r.headers)
        findings.extend(_method_findings(client, base_url))
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings), stderr="", duration_s=duration,
    )
