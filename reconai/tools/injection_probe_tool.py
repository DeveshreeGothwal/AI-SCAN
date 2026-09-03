from __future__ import annotations

import concurrent.futures
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# The pip HTTP client library (see requirements.txt) -- NOT ProjectDiscovery's Go
# recon tool of the same name (that one is reconai/tools/httpx_tool.py).
import httpx

from .base import ProxyUnavailable, ToolResult, httpx_client
from .mock_data import MOCK_OUTPUTS

NAME = "injection_probe"

# Bounds request volume: cap total (url, param) combinations tested rather than
# testing every parameter of every discovered URL, which could balloon into
# hundreds of requests against the target for a single pipeline stage.
_MAX_PAIRS = 15
_REQUEST_TIMEOUT = 6.0
_WORKERS = 5

# Only high-confidence, low-false-positive signatures -- e.g. no boolean-based
# SQLi diffing (too noisy without a stable baseline) and no time-based checks
# (slow, and blind timing signals are weak evidence for an unattended scan).
_SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*\Wmysqli?_", r"Unclosed quotation mark",
    r"quoted string not properly terminated", r"ORA-\d{5}", r"PostgreSQL.*ERROR",
    r"SQLSTATE\[", r"SQLite3::query", r"Microsoft OLE DB Provider for SQL Server",
]
_SSTI_PROBES = [("{{7*7}}", "Jinja2"), ("${7*7}", "Mako"), ("<%= 7*7 %>", "ERB")]
_SSTI_BASELINE_VALUE = "reconai-ssti-baseline-check"
# Reflected XSS: a distinctive marker tag that would only ever appear
# verbatim in the response if user input reaches the page HTML-unescaped --
# read-only text-reflection evidence, exactly like every other check in this
# file. Nothing here is a real payload: no browser/JS engine is involved, so
# it never actually executes against anyone, it only proves the escaping gap
# exists. The leading "><' breaks out of a quoted attribute or tag context,
# which is where most reflected-XSS sinks actually live.
_XSS_MARKER = "reconaixsscanary"
_XSS_PAYLOAD = f"\"'><{_XSS_MARKER}>"
# Word-boundary, not a bare substring check -- verified against a real false
# positive: a security-advisory page listing malware SHA-256 hashes as IOCs
# contained "49" as a substring inside a hash (...f3ec59d0**49**2e9b...),
# which a bare "49" in r.text would flag as "evaluated to 49" even though the
# payload was never reflected at all. \b49\b doesn't match inside a
# contiguous run of hex digits, so it only fires on 49 as its own token.
_SSTI_RESULT_RE = re.compile(r"\b49\b")
_CMDI_PATTERN = re.compile(r"uid=\d+\([a-zA-Z0-9_.-]+\)\s+gid=\d+")
_PATH_TRAVERSAL_PATTERN = re.compile(r"root:.*:0:0:")
_REDIRECT_PARAM_RE = re.compile(r"redirect|url|next|return|dest|continue|target|location|out|view|navigate", re.IGNORECASE)
_REDIRECT_MARKER = "https://reconai-redirect-check.invalid"

# SSRF is not auto-probed (safely confirming it needs an out-of-band callback
# listener to catch a server-side request -- standing up that infrastructure
# is out of scope for an unattended, cost-free recon tool). Instead, parameter
# names with a known SSRF-prone shape are statically flagged from data already
# collected by waybackurls, for a human to manually test -- zero extra
# requests, matches how experienced hunters triage recon output before
# spending manual effort ("recon wins" pattern from published SSRF writeups).
_SSRF_PARAM_RE = re.compile(
    r"^(url|uri|path|dest|redirect|continue|return|src|source|feed|callback|webhook|proxy|"
    r"fetch|load|target|out|view|show|navigate|image|avatar|file|link|site|domain|host|page)$",
    re.IGNORECASE,
)


def _params_of(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def _original_value(url: str, param: str) -> str:
    values = parse_qs(urlparse(url).query, keep_blank_values=True).get(param, [""])
    return values[0] if values else ""


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _probe_pair(client: httpx.Client, url: str, param: str) -> list[str]:
    findings: list[str] = []
    original = _original_value(url, param)

    # SQL injection: error-based only. A leaked SQL error is unambiguous
    # evidence; append (not replace) so fields expecting a valid-looking
    # original value still reach the vulnerable code path.
    try:
        r = client.get(_with_param(url, param, original + "'"))
        if any(re.search(p, r.text, re.IGNORECASE) for p in _SQLI_ERROR_PATTERNS):
            findings.append(f"[SQL Injection] param '{param}' on {url} -- SQL error signature after appending a single quote")
    except httpx.HTTPError:
        pass

    # Command injection: benign, read-only "id" probe appended to the
    # original value -- looks for the specific uid=/gid= shape, never a
    # destructive payload or reverse shell.
    try:
        r = client.get(_with_param(url, param, f"{original}; id"))
        if _CMDI_PATTERN.search(r.text):
            findings.append(f"[Command Injection] param '{param}' on {url} -- 'id' command output reflected in response")
    except httpx.HTTPError:
        pass

    # Server-side template injection: math-eval reflection, per engine.
    # Baselined against a harmless control value for the same param first --
    # verified for real against a live target that renders a server-side
    # clock into every response: a bare \b49\b check alone false-positived
    # as "template injection" on nearly every parameter, purely because the
    # live HH:MM:SS happened to show ":49" for the minute or second field at
    # that moment, completely independent of the injected payload. Only "49"
    # that appears in the payload response but NOT in a same-shape baseline
    # response counts as evidence.
    try:
        baseline_r = client.get(_with_param(url, param, _SSTI_BASELINE_VALUE))
        baseline_has_49 = bool(_SSTI_RESULT_RE.search(baseline_r.text))
    except httpx.HTTPError:
        baseline_has_49 = True  # can't establish a clean baseline -- fail closed, skip this check

    for payload, engine in _SSTI_PROBES:
        try:
            r = client.get(_with_param(url, param, payload))
            if not baseline_has_49 and _SSTI_RESULT_RE.search(r.text) and payload not in r.text:
                findings.append(f"[Template Injection ({engine})] param '{param}' on {url} -- {payload} evaluated to 49")
                break
        except httpx.HTTPError:
            pass

    # Reflected XSS: the marker tag only appears literally in a well-behaved
    # app if it HTML-escapes '<'/'>'/'"' -- a real app would render
    # "&lt;reconaixsscanary&gt;", so an exact unescaped match is strong,
    # low-false-positive evidence.
    try:
        r = client.get(_with_param(url, param, original + _XSS_PAYLOAD))
        if f"<{_XSS_MARKER}>" in r.text:
            findings.append(f"[Reflected XSS] param '{param}' on {url} -- injected marker reflected unescaped in response")
    except httpx.HTTPError:
        pass

    # Path traversal: read-only file-signature check.
    try:
        r = client.get(_with_param(url, param, "../../../../../../etc/passwd"))
        if _PATH_TRAVERSAL_PATTERN.search(r.text):
            findings.append(f"[Path Traversal] param '{param}' on {url} -- /etc/passwd content in response")
    except httpx.HTTPError:
        pass

    # Open redirect: only for params whose name suggests redirect intent.
    if _REDIRECT_PARAM_RE.search(param):
        try:
            r = client.get(_with_param(url, param, _REDIRECT_MARKER), follow_redirects=False)
            if _REDIRECT_MARKER in r.headers.get("location", ""):
                findings.append(f"[Open Redirect] param '{param}' on {url} -- Location header points at an attacker-controlled URL")
        except httpx.HTTPError:
            pass

    return findings


def _flag_ssrf_prone_params(param_urls: list[str]) -> list[str]:
    return sorted({
        f"param '{param}' on {url}"
        for url in param_urls
        for param in _params_of(url)
        if _SSRF_PARAM_RE.match(param)
    })


def _format_findings(findings: list[str], num_urls: int, num_pairs: int, ssrf_flagged: list[str]) -> str:
    header = f"Probed {num_urls} parameterized URL(s), {num_pairs} parameter(s) tested."
    body = header + ("\n\nNo injection signatures detected in the tested parameters." if not findings
                      else "\n\n" + "\n".join(findings))
    if ssrf_flagged:
        body += (
            "\n\n[Informational] parameter name(s) suggestive of SSRF -- not auto-tested "
            "(safely confirming SSRF needs an out-of-band callback listener, out of scope "
            "here), flagged for manual review:\n" + "\n".join(ssrf_flagged)
        )
    return body


def run(param_urls: list[str], dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-injection-probe", f"--urls={len(param_urls)}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=(f"[DRY-RUN] would probe {len(param_urls)} parameterized URL(s) for "
                    "SQLi/command-injection/SSTI/path-traversal/open-redirect/reflected-XSS"),
            stderr="", duration_s=0.0,
        )

    pairs: list[tuple[str, str]] = []
    for url in param_urls:
        for param in _params_of(url):
            pairs.append((url, param))
            if len(pairs) >= _MAX_PAIRS:
                break
        if len(pairs) >= _MAX_PAIRS:
            break

    start = time.monotonic()
    findings: list[str] = []
    try:
        client_cm = httpx_client(proxy=proxy, timeout=_REQUEST_TIMEOUT, verify=False)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    with client_cm as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = [pool.submit(_probe_pair, client, url, param) for url, param in pairs]
            for future in concurrent.futures.as_completed(futures):
                findings.extend(future.result())
    duration = time.monotonic() - start

    return ToolResult(
        tool=NAME, command=cmd, available=True, returncode=0,
        stdout=_format_findings(findings, len(param_urls), len(pairs), _flag_ssrf_prone_params(param_urls)),
        stderr="", duration_s=duration,
    )
