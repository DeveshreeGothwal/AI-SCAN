from __future__ import annotations

import re
import time

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "privacy_scan"

_TIMEOUT = 8.0

# Small, curated signatures -- not exhaustive, just the handful common enough
# to be worth a zero-config check. Same spirit as base.py's APT_HINTS: a
# short, honest built-in list rather than a heavyweight external dependency.
_TRACKER_SIGNATURES = (
    "googletagmanager.com", "google-analytics.com", "gtag(", "ga('create'",
    "connect.facebook.net", "fbq(",
    "hotjar.com", "analytics.tiktok.com",
)
_CONSENT_MARKERS = (
    "cookieconsent", "cookie-consent", "cookie_consent", "onetrust",
    "gdpr-consent", "cookie-notice", "cookiebanner", "cookie-banner",
)


def _tracker_findings(body: str) -> list[str]:
    lowered = body.lower()
    trackers_found = [sig for sig in _TRACKER_SIGNATURES if sig.lower() in lowered]
    if not trackers_found:
        return []
    has_consent_marker = any(marker in lowered for marker in _CONSENT_MARKERS)
    if has_consent_marker:
        return []
    shown = ", ".join(trackers_found[:3]) + (f" (+{len(trackers_found) - 3} more)" if len(trackers_found) > 3 else "")
    return [f"[Tracking Without Consent Signal] tracker script(s) detected ({shown}) with no "
            "cookie-consent/CMP marker found in the same response -- trackers may be loading "
            "before any consent is given"]


def _header_findings(headers: httpx.Headers) -> list[str]:
    findings = []
    referrer_policy = (headers.get("referrer-policy") or "").lower()
    if not referrer_policy or referrer_policy == "unsafe-url":
        findings.append("[Weak Referrer Policy] Referrer-Policy header is "
                         + ("missing" if not referrer_policy else "set to 'unsafe-url'")
                         + " -- the full URL (which can contain sensitive query parameters) may leak "
                           "to third parties via the Referer header on outbound links")
    if headers.get("permissions-policy") is None and headers.get("feature-policy") is None:
        findings.append("[Missing Permissions-Policy] no Permissions-Policy/Feature-Policy header -- "
                         "embedded third-party content has no explicit restriction on accessing "
                         "camera, microphone, or geolocation")
    return findings


def _format_findings(findings: list[str]) -> str:
    if not findings:
        return "No tracking-without-consent signals or missing privacy-related headers detected."
    return "\n".join(findings)


def run(base_url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-privacy-scan", f"--base-url={base_url}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would check {base_url} for trackers loaded without a consent signal, "
                   "and for missing Referrer-Policy/Permissions-Policy headers",
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
        findings = _header_findings(r.headers)
        findings.extend(_tracker_findings(r.text))
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings), stderr="", duration_s=duration,
    )
