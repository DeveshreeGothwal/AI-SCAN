from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client, registrable_domain, run_command
from .mock_data import MOCK_OUTPUTS

NAME = "link_safety"

# Standalone, user-facing safety check for a URL someone received (email/SMS/
# chat) -- deliberately NOT wired into the authorized-scan pipeline. Checking
# whether a link you were sent looks safe is a self-protective action with no
# third-party authorization question, unlike scanning a target: nothing here
# does more than a browser opening the same link would already do (one GET
# following redirects, one WHOIS lookup on the domain).

_TIMEOUT = 8.0
_MAX_REDIRECTS_BEFORE_FLAG = 2

# Small, curated lists -- not exhaustive, just the handful common enough to be
# worth a zero-config, no-API-key heuristic. Same spirit as base.py's
# APT_HINTS / _MULTI_PART_SUFFIXES: an honest built-in list, not a claim of
# completeness.
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}
_SUSPICIOUS_TLDS = {"zip", "top", "xyz", "work", "click", "country", "gq", "tk", "cf", "mov"}
_IMPERSONATION_KEYWORDS = (
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "irs", "bankofamerica", "chase", "wellsfargo",
)
_WHOIS_CREATION_DATE_RE = re.compile(r"creation date:\s*([\d-]{10})", re.IGNORECASE)
_NEWLY_REGISTERED_DAYS = 30

# (weight, tag) -- verdict is derived from the sum of weights of findings that
# actually fired, not just a raw count, so a single high-confidence signal
# (punycode, brand impersonation) outweighs several minor ones.
_WEIGHTS = {
    "[Insecure Connection]": 1, "[IP Address Host]": 2, "[Punycode/Homograph Domain]": 3,
    "[Possible Brand Impersonation]": 3, "[Shortened URL]": 1, "[Long Redirect Chain]": 1,
    "[Elevated-Risk TLD]": 1, "[Newly Registered Domain]": 2,
}


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _static_findings(url: str) -> list[str]:
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme != "https":
        findings.append("[Insecure Connection] no HTTPS -- data sent to/from this link isn't encrypted")

    if _is_ip_literal(hostname):
        findings.append(f"[IP Address Host] the link points directly at an IP address ({hostname}) "
                         "rather than a domain name -- a common way to obscure the true destination")

    if "xn--" in hostname.lower():
        findings.append(f"[Punycode/Homograph Domain] hostname '{hostname}' contains punycode-encoded "
                         "characters -- often used to visually impersonate a trusted domain with "
                         "lookalike characters")

    if hostname and not _is_ip_literal(hostname):
        apex = registrable_domain(hostname)
        brand_hit = next((kw for kw in _IMPERSONATION_KEYWORDS
                           if kw in hostname.lower() and not apex.lower().startswith(kw)), None)
        if brand_hit:
            findings.append(f"[Possible Brand Impersonation] hostname contains '{brand_hit}' but the "
                             f"actual domain is '{apex}', not {brand_hit}'s real domain -- a classic "
                             "phishing pattern")

    if hostname.lower() in _URL_SHORTENERS:
        findings.append(f"[Shortened URL] '{hostname}' is a link shortener -- the real destination is "
                         "hidden until you follow it")

    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
    if tld in _SUSPICIOUS_TLDS:
        findings.append(f"[Elevated-Risk TLD] .{tld} is disproportionately used in abuse campaigns -- "
                         "not proof of malice on its own, just an elevated-risk signal")

    return findings


def _redirect_findings(client: httpx.Client, url: str) -> list[str]:
    try:
        r = client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    hops = len(r.history)
    if hops == 0:
        return []
    findings = [f"[Informational] {hops} redirect(s) -- final destination: {r.url}"]
    if hops > _MAX_REDIRECTS_BEFORE_FLAG:
        findings.append(f"[Long Redirect Chain] {hops} redirects before reaching the final "
                         "destination -- can be used to hide the real target from a quick glance")
    return findings


def _domain_age_findings(hostname: str, proxy: str | None) -> list[str]:
    if not hostname or _is_ip_literal(hostname):
        return []
    apex = registrable_domain(hostname)
    result = run_command(f"{NAME}-whois", ["whois", apex], timeout=15, proxy=proxy)
    if not result.available:
        return []
    match = _WHOIS_CREATION_DATE_RE.search(result.stdout)
    if not match:
        return []
    try:
        created = datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
    except ValueError:
        return []
    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < _NEWLY_REGISTERED_DAYS:
        return [f"[Newly Registered Domain] registered {age_days} day(s) ago -- freshly-registered "
                "domains are disproportionately used in phishing/scam campaigns"]
    return []


def _verdict(findings: list[str]) -> str:
    score = sum(weight for tag, weight in _WEIGHTS.items() if any(f.startswith(tag) for f in findings))
    if score >= 4:
        return "HIGH RISK"
    if score >= 1:
        return "USE CAUTION"
    return "LOOKS SAFE"


def _format_findings(findings: list[str], url: str) -> str:
    header = f"Checked {url}"
    body_findings = [f for f in findings if not f.startswith("[Informational]")]
    verdict_line = f"Verdict: {_verdict(findings)}"
    if not body_findings:
        return f"{header}\n\n{verdict_line}\n\nNo risk signals detected.\n\n" + "\n".join(
            f for f in findings if f.startswith("[Informational]"))
    return f"{header}\n\n{verdict_line}\n\n" + "\n".join(findings)


def run(url: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-link-safety", f"--url={url}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"[DRY-RUN] would check {url} for insecure connection, IP-literal/punycode/"
                   "impersonation hostname patterns, shortener/redirect-chain behavior, suspicious "
                   "TLD, and domain age",
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    findings = _static_findings(url)
    hostname = urlparse(url).hostname or ""

    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        findings.extend(_redirect_findings(client, url))

    findings.extend(_domain_age_findings(hostname, proxy=proxy))
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, url), stderr="", duration_s=duration,
    )
