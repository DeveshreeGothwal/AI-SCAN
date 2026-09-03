from __future__ import annotations

import concurrent.futures
import contextlib
import re
import time

import httpx  # the pip HTTP client library (requirements.txt)

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "secret_scan"

_TIMEOUT = 6.0
_WORKERS = 8
_MAX_JS_FILES = 15

# Only high-confidence, format-specific patterns -- no generic "password=" /
# "api_key=" style regexes, which are far too noisy for an unattended scan.
_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Private Key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

_CONFIG_PATHS = [".env", ".env.local", ".env.production", "config/.env", "wp-config.php.bak", ".git/config"]
_CONFIG_SIGNATURES = [
    re.compile(r"^[A-Z_]+=.+$", re.MULTILINE),  # KEY=value .env-style lines
    re.compile(r"\[core\]"),                     # .git/config
]

# Opt-in validation: exactly one read-only confirmatory call to the
# credential's own provider, mirroring how github_secrets_tool.py always
# uses trufflehog's --only-verified. Only wired up for secret types that are
# (a) usable alone, unlike an AWS access key ID which needs a paired secret
# key we don't capture, and (b) checkable with a call that has no side
# effects -- Slack's auth.test is Slack's own documented no-op token check
# (it does not post to any channel), unlike posting a message via a webhook.
_VALIDATE_TIMEOUT = 8.0


def _validate_stripe_key(client: httpx.Client, key: str) -> str:
    try:
        r = client.get("https://api.stripe.com/v1/charges", params={"limit": 1}, auth=(key, ""))
    except httpx.HTTPError:
        return "could not verify (network error)"
    if r.status_code == 200:
        return "VERIFIED LIVE"
    if r.status_code == 401:
        return "invalid/revoked"
    return f"verification inconclusive (HTTP {r.status_code})"


def _validate_slack_token(client: httpx.Client, token: str) -> str:
    try:
        r = client.post("https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {token}"})
        ok = r.json().get("ok")
    except (httpx.HTTPError, ValueError):
        return "could not verify (network error)"
    return "VERIFIED LIVE" if ok else "invalid/revoked"


_VALIDATORS = {
    "Stripe Secret Key": _validate_stripe_key,
    "Slack Token": _validate_slack_token,
}


def _scan_text(source: str, text: str, validate_client: httpx.Client | None = None) -> list[str]:
    findings = []
    for label, pattern in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            value = match.group(0)
            line = f"[{label}] found in {source}: {value[:12]}..."
            validator = _VALIDATORS.get(label)
            if validate_client is not None and validator is not None:
                line += f" -- {validator(validate_client, value)}"
            findings.append(line)
    return findings


def _fetch(client: httpx.Client, url: str) -> str | None:
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code == 200:
        return r.text
    return None


def _check_config_path(client: httpx.Client, base_url: str, path: str,
                        validate_client: httpx.Client | None = None) -> list[str]:
    url = f"{base_url.rstrip('/')}/{path}"
    text = _fetch(client, url)
    if text is None:
        return []
    findings = _scan_text(url, text, validate_client)
    if any(sig.search(text) for sig in _CONFIG_SIGNATURES):
        findings.append(f"[Exposed config file] {url} is accessible and looks like real config content")
    return findings


def _check_js(client: httpx.Client, url: str, validate_client: httpx.Client | None = None) -> list[str]:
    text = _fetch(client, url)
    if text is None:
        return []
    return _scan_text(url, text, validate_client)


def _format_findings(findings: list[str], num_js: int, num_paths: int) -> str:
    header = f"Scanned {num_js} JS file(s) and {num_paths} common config path(s)."
    if not findings:
        return header + "\n\nNo secrets or exposed config files detected."
    return header + "\n\n" + "\n".join(findings)


def run(base_url: str, js_urls: list[str], dry_run: bool = False, mock: bool = False,
        proxy: str | None = None, validate: bool = False) -> ToolResult:
    js_urls = js_urls[:_MAX_JS_FILES]
    cmd = ["reconai-secret-scan", f"--base-url={base_url}", f"--js-files={len(js_urls)}"]
    if validate:
        cmd.append("--validate")

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        validate_note = (" and validate any Stripe/Slack secrets found with one confirmatory call each"
                          if validate else "")
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=(f"[DRY-RUN] would scan {len(js_urls)} JS file(s) and "
                    f"{len(_CONFIG_PATHS)} common config path(s) for secrets{validate_note}"),
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    findings: list[str] = []
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))

    # Validation is a bonus, opt-in enhancement on top of the core scan -- if
    # the proxy can't support a second client for some reason, skip
    # validation rather than failing the whole tool over it.
    validate_cm = None
    if validate:
        try:
            validate_cm = httpx_client(proxy=proxy, timeout=_VALIDATE_TIMEOUT)
        except ProxyUnavailable:
            validate_cm = None

    with contextlib.ExitStack() as stack:
        client = stack.enter_context(client_cm)
        validate_client = stack.enter_context(validate_cm) if validate_cm is not None else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = [pool.submit(_check_js, client, url, validate_client) for url in js_urls]
            futures += [pool.submit(_check_config_path, client, base_url, path, validate_client)
                        for path in _CONFIG_PATHS]
            for future in concurrent.futures.as_completed(futures):
                findings.extend(future.result())
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(js_urls), len(_CONFIG_PATHS)),
        stderr="", duration_s=duration,
    )
