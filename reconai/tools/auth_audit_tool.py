from __future__ import annotations

import concurrent.futures
import re
import time
from urllib.parse import urljoin, urlparse

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "auth_audit"

_TIMEOUT = 6.0
_WORKERS = 5
_MAX_CANDIDATES = 12
_COMMON_PATHS = [
    "/login", "/signin", "/sign-in", "/register", "/signup", "/sign-up",
    "/account/login", "/user/login", "/admin/login", "/wp-login.php",
]
# A candidate is only analyzed if it actually looks like a real auth form --
# a generic "not found" or marketing page shouldn't be scored at all.
_PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE)
_MAXLENGTH_RE = re.compile(r'<input[^>]+type=["\']password["\'][^>]*maxlength=["\']?(\d+)', re.IGNORECASE)
_CSRF_NAME_RE = re.compile(r'name=["\'][^"\']*(csrf|_token|authenticity_token)[^"\']*["\']', re.IGNORECASE)
_FORM_RE = re.compile(r"<form", re.IGNORECASE)
_MIN_PASSWORD_MAXLENGTH = 12


def discover_candidates(base_url: str, *sources: str) -> list[str]:
    """Common auth-related paths plus anything login/register-looking already
    mentioned in getjs/linkfinder/waybackurls output -- same shape as
    graphql_probe_tool.discover_candidates, reusing recon already gathered
    instead of crawling again."""
    candidates = [urljoin(base_url + "/", path.lstrip("/")) for path in _COMMON_PATHS]
    seen = set(candidates)
    keywords = ("login", "signin", "sign-in", "register", "signup", "sign-up", "auth")
    for source in sources:
        for line in source.splitlines():
            line = line.strip()
            if not any(kw in line.lower() for kw in keywords):
                continue
            url = line if line.startswith("http") else urljoin(base_url + "/", line.lstrip("/"))
            if url not in seen:
                seen.add(url)
                candidates.append(url)
    return candidates[:_MAX_CANDIDATES]


def _analyze_form(url: str, body: str) -> list[str]:
    findings = []

    if urlparse(url).scheme == "http":
        findings.append(f"[Cleartext Credential Submission] {url} -- password form served over "
                         "plain HTTP; credentials are sent unencrypted and can be intercepted "
                         "by anyone on the network path")

    maxlength_match = _MAXLENGTH_RE.search(body)
    if maxlength_match and int(maxlength_match.group(1)) < _MIN_PASSWORD_MAXLENGTH:
        findings.append(f"[Weak Password Policy] {url} -- password field caps input at "
                         f"{maxlength_match.group(1)} characters, well below a reasonable minimum")

    if not _CSRF_NAME_RE.search(body):
        findings.append(f"[Missing CSRF Protection] {url} -- no hidden field matching a common "
                         "CSRF-token naming pattern found (heuristic: name-based, not a guarantee "
                         "the form actually lacks CSRF protection)")

    return findings


def _probe(client: httpx.Client, url: str) -> list[str]:
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return []
    if r.status_code >= 400:
        return []
    body = r.text
    if not (_FORM_RE.search(body) and _PASSWORD_INPUT_RE.search(body)):
        return []  # not a real auth form -- nothing to score here
    return _analyze_form(url, body)


def _format_findings(findings: list[str], num_candidates: int) -> str:
    header = f"Probed {num_candidates} candidate authentication endpoint(s)."
    if not findings:
        return header + "\n\nNo login/registration forms found, or every form found looked properly hardened."
    body = header + "\n\n" + "\n".join(findings)
    body += ("\n\n[Informational] account lockout / rate-limiting was not tested -- doing so would "
             "require repeated login attempts against a real account, which this tool deliberately "
             "never does. Verify this manually/internally.")
    return body


def run(base_url: str, extra_sources: list[str] | None = None, dry_run: bool = False, mock: bool = False,
        proxy: str | None = None) -> ToolResult:
    candidates = discover_candidates(base_url, *(extra_sources or []))
    cmd = ["reconai-auth-audit", f"--base-url={base_url}", f"--candidates={len(candidates)}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=(f"[DRY-RUN] would check {len(candidates)} candidate authentication endpoint(s) for "
                    "cleartext credential submission, weak password policy, and missing CSRF protection"),
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
            futures = [pool.submit(_probe, client, url) for url in candidates]
            for future in concurrent.futures.as_completed(futures):
                findings.extend(future.result())
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(candidates)),
        stderr="", duration_s=duration,
    )
