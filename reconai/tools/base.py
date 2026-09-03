from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx  # the pip HTTP client library (requirements.txt)

# ~/go/bin isn't on PATH by default, and some binary names collide with
# unrelated apt packages (e.g. apt's "httpx" is a Python HTTP client, not
# ProjectDiscovery's recon tool) -- resolve these by absolute path instead
# of trusting bare names on PATH.
GO_BIN = Path.home() / "go" / "bin"
LINKFINDER_DIR = Path.home() / "LinkFinder"
LINKFINDER_PYTHON = str(LINKFINDER_DIR / "venv" / "bin" / "python3")
LINKFINDER_SCRIPT = str(LINKFINDER_DIR / "linkfinder.py")

_HTTPX_BIN = str(GO_BIN / "httpx")
_GETJS_BIN = str(GO_BIN / "getJS")
_SUBJACK_BIN = str(GO_BIN / "subjack")
_WAYBACKURLS_BIN = str(GO_BIN / "waybackurls")
_TRUFFLEHOG_BIN = str(GO_BIN / "trufflehog")
_PROXYCHAINS_BIN = "proxychains4"

# Common multi-part public suffixes -- not a full public-suffix-list
# dependency (kept self-contained), just the ones common enough to actually
# bite the "org name = label before the TLD" heuristic below.
_MULTI_PART_SUFFIXES = {
    "co.uk", "gov.uk", "org.uk", "ac.uk", "nhs.uk", "sch.uk",
    "co.in", "gov.in", "org.in", "ac.in", "net.in", "res.in", "nic.in",
    "co.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "gov.au", "org.au", "edu.au", "net.au",
    "co.nz", "govt.nz", "org.nz", "ac.nz",
    "com.br", "gov.br", "org.br",
    "co.za", "gov.za", "org.za",
    "com.cn", "gov.cn", "org.cn",
    "co.id", "go.id", "or.id",
}


def guess_org_name(target: str) -> str:
    """Best-effort company/org-name guess from a domain: the label right
    before the registrable-domain boundary. Handles common multi-part public
    suffixes (.co.uk, .gov.in, etc.) via the small built-in list above rather
    than a full public-suffix-list dependency -- verified needed for real:
    "www.csk.gov.in" naively guessed "gov" (just the label before the TLD)
    instead of "csk", which would point bucket_enum/github_secrets at an
    unrelated, wildly common "gov"-named bucket/org rather than the actual
    target -- a real authorization-boundary risk for github_secrets
    specifically (cloning and scanning a GitHub org that isn't the
    authorized target). Still a best-effort guess for suffixes not in this
    list, and for orgs whose name doesn't match their domain at all -- not a
    guarantee either way."""
    labels = target.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def registrable_domain(target: str) -> str:
    """Reduce a hostname to its registrable (apex) domain, e.g.
    "www.banasthali.org" -> "banasthali.org". Passive subdomain-discovery
    sources (subfinder, crt.sh) need the apex domain to find sibling
    subdomains -- verified for real against a live target: subfinder/crt.sh
    queried with the literal scanned hostname "www.banasthali.org" both
    returned zero results (there's no such thing as a sub-subdomain of a
    "www" host), while the same queries against the apex "banasthali.org"
    turned up 11 real subdomains. Uses the same built-in multi-part-suffix
    list as guess_org_name() above rather than a full public-suffix-list
    dependency."""
    labels = target.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else target

# getJS and subjack are small Go binaries that don't expose a --proxy flag and
# were empirically confirmed (via a local test listener) to honor neither
# HTTP_PROXY/HTTPS_PROXY env vars nor proxychains4's LD_PRELOAD interception --
# both silently dial out directly regardless. Every other tool in this project
# was verified to route through a proxy via one of: its own native --proxy
# flag, Go's default net/http transport respecting the env vars, or
# proxychains4 (works for anything dynamically linked against libc: whois,
# dig, nmap, Python/Ruby/Perl/bash tools). Rather than silently leak direct
# connections from these two when a proxy is requested, run_command() below
# refuses to run them at all in that case.
PROXY_UNSUPPORTED_BINARIES = {_GETJS_BIN, _SUBJACK_BIN}

# waybackurls and trufflehog are Go binaries too, but (unlike getJS/subjack)
# were confirmed to actually dial out via Go's default net/http transport,
# which honors these env vars directly. Critically: proxychains4 must NOT
# also wrap these calls -- confirmed by reproducing a real failure (curl
# returning "Failed to connect... Could not connect to server" the moment
# both HTTPS_PROXY and a proxychains wrapper were active together). Any
# binary that reads the proxy env vars itself will try to dial the proxy
# address directly, and proxychains intercepts *that* connection attempt too,
# looping it back through the same proxy a second time. So env-var proxying
# and proxychains wrapping are mutually exclusive per call, never combined.
ENV_VAR_PROXY_BINARIES = {_WAYBACKURLS_BIN, _TRUFFLEHOG_BIN}

APT_HINTS = {
    "whois": "whois",
    "dig": "dnsutils",
    "dnsrecon": "dnsrecon",
    "subfinder": "subfinder (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)",
    "theHarvester": "theharvester",
    "nmap": "nmap",
    "whatweb": "whatweb",
    "nikto": "nikto",
    "gobuster": "gobuster",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
    "wafw00f": "wafw00f",
    "testssl": "testssl.sh",
    "gowitness": "gowitness",
    "sqlmap": "sqlmap",
    "git": "git",
    _HTTPX_BIN: (
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest "
        "(installs to ~/go/bin -- the apt 'httpx' package is an unrelated Python HTTP client)"
    ),
    _GETJS_BIN: "go install -v github.com/003random/getJS/v2@latest",
    _SUBJACK_BIN: "go install -v github.com/haccer/subjack@latest",
    _WAYBACKURLS_BIN: "go install -v github.com/tomnomnom/waybackurls@latest",
    _TRUFFLEHOG_BIN: (
        "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh "
        "| sh -s -- -b ~/go/bin (installs to ~/go/bin -- `go install` doesn't work for trufflehog, "
        "its go.mod has a replace directive that go install rejects)"
    ),
    _PROXYCHAINS_BIN: "proxychains4",
    LINKFINDER_PYTHON: (
        "git clone https://github.com/GerbenJavado/LinkFinder.git ~/LinkFinder && "
        "cd ~/LinkFinder && python3 -m venv venv && venv/bin/pip install setuptools -r requirements.txt"
    ),
}


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    available: bool
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    skipped_reason: str | None = None
    mocked: bool = False
    extra: dict = field(default_factory=dict)


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def apt_hint(binary: str) -> str:
    return APT_HINTS.get(binary, binary)


_PROXY_SCHEME_TO_PROXYCHAINS_TYPE = {
    "socks5": "socks5", "socks5h": "socks5", "socks4": "socks4",
    "http": "http", "https": "http",
}
_PROXYCHAINS_DEFAULT_PORTS = {"socks5": 1080, "socks4": 1080, "http": 8080}


def proxy_env_vars(proxy: str | None) -> dict[str, str]:
    """Standard proxy env vars, both cases (some tools only check one), for
    anything that reads the environment for its proxy config -- Go's default
    net/http transport (waybackurls, trufflehog), Python's requests/urllib3
    (theHarvester, wafw00f), and most other language HTTP stacks."""
    if proxy is None:
        return {}
    return {
        "HTTP_PROXY": proxy, "http_proxy": proxy,
        "HTTPS_PROXY": proxy, "https_proxy": proxy,
        "ALL_PROXY": proxy, "all_proxy": proxy,
    }


def _proxychains_config_path(proxy: str, proxy_dns: bool) -> Path:
    parsed = urlparse(proxy)
    proxy_type = _PROXY_SCHEME_TO_PROXYCHAINS_TYPE.get(parsed.scheme.lower())
    if proxy_type is None:
        raise ValueError(f"unsupported proxy scheme '{parsed.scheme}' -- use socks5, socks4, or http")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or _PROXYCHAINS_DEFAULT_PORTS[proxy_type]
    # Regenerated fresh each call (cheap -- a few lines of text) rather than
    # threaded through every caller as a Path -- one proxy URL per pipeline
    # run in practice, so there's nothing meaningful to cache. Two filenames
    # (not one) so a dns-mode and a non-dns-mode call in the same run don't
    # clobber each other if they happen to interleave.
    config_path = Path(tempfile.gettempdir()) / f"reconai-proxychains{'' if proxy_dns else '-nodns'}.conf"
    config_path.write_text(
        "strict_chain\n"
        + ("proxy_dns\nremote_dns_subnet 224\n" if proxy_dns else "")
        + "tcp_read_time_out 15000\n"
          "tcp_connect_time_out 8000\n"
          "[ProxyList]\n"
        + f"{proxy_type} {host} {port}\n"
    )
    return config_path


def wrap_with_proxychains(cmd: list[str], proxy: str | None, proxy_dns: bool = True) -> list[str]:
    """Prefix cmd with proxychains4 so tools with no native proxy support (and
    no other way to reach one) get routed anyway -- reliable for anything
    dynamically linked against libc (whois, dig, nmap, Python/Ruby/Perl/bash
    tools); a no-op in practice for Go binaries with their own --proxy flag,
    since those are handled by the tool module adding the flag itself, not by
    this wrapping. See PROXY_UNSUPPORTED_BINARIES for the (empirically
    verified) cases where neither mechanism works.

    proxy_dns additionally routes the *hostname resolution* itself through
    the proxy (so the target's hostname isn't leaked via a direct, unproxied
    DNS lookup before the proxied connection is even made) -- on by default.
    `dig` specifically fails to even start with it on (verified: "parse of
    /etc/resolv.conf failed" -- proxychains' DNS interception is incompatible
    with dig's own resolver initialization), so dns_tool/dns_axfr_tool pass
    proxy_dns=False; the zone-transfer/record data itself is still proxied
    (confirmed via a local test listener), only dig's own upstream-nameserver
    lookup falls back to the local resolver in that one case.
    """
    if proxy is None:
        return cmd
    config_path = _proxychains_config_path(proxy, proxy_dns)
    return [_PROXYCHAINS_BIN, "-q", "-f", str(config_path), *cmd]


class ProxyUnavailable(Exception):
    """Raised when a proxy was requested but can't actually be used (missing
    proxychains4, or httpx's optional socksio dependency for a socks:// URL)."""


def httpx_client(proxy: str | None = None, **kwargs) -> httpx.Client:
    """httpx.Client construction shared by every in-process (non-subprocess)
    tool, so proxy support and its failure mode live in one place. A socks://
    proxy needs the optional `socksio` package (httpx[socks]) -- without it
    httpx raises ImportError at construction time, which we turn into
    ProxyUnavailable so callers can report a clean skipped ToolResult instead
    of crashing the pipeline stage."""
    try:
        return httpx.Client(proxy=proxy, **kwargs)
    except ImportError as exc:
        raise ProxyUnavailable(
            f"proxy requested but a required package is missing ({exc}). "
            "Install with: pip install httpx[socks]"
        ) from exc


def run_command(
    tool_name: str,
    cmd: list[str],
    timeout: int = 300,
    dry_run: bool = False,
    mock_output: str | None = None,
    proxy: str | None = None,
    proxy_flag_added: bool = False,
    proxy_dns: bool = True,
) -> ToolResult:
    """proxy_flag_added=True means the caller already appended the tool's own
    native --proxy-style flag to cmd (the most reliable mechanism where one
    exists) -- in that case this skips the proxychains4 wrapping/dependency
    entirely rather than layering a redundant, proxychains4-requiring no-op
    around a command that doesn't need it."""
    binary = cmd[0]

    if not is_available(binary):
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=False,
            returncode=None,
            stdout="",
            stderr="",
            duration_s=0.0,
            skipped_reason=(
                f"'{binary}' not found on PATH. Install with: sudo apt install {apt_hint(binary)}"
            ),
        )

    if mock_output is not None:
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=0,
            stdout=mock_output,
            stderr="",
            duration_s=0.0,
            mocked=True,
        )

    if proxy is not None and binary in PROXY_UNSUPPORTED_BINARIES:
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=False,
            returncode=None,
            stdout="",
            stderr="",
            duration_s=0.0,
            skipped_reason=(
                f"proxy mode is on, but '{binary}' was verified to not honor it (neither env-var "
                "proxying nor proxychains4 catches its connections) -- skipped rather than silently "
                "running it unproxied. Re-run without a proxy if you need this tool's data."
            ),
        )

    # Mutually exclusive, never combined: a binary either reads the proxy env
    # vars itself (ENV_VAR_PROXY_BINARIES) or gets proxychains-wrapped, not
    # both -- see ENV_VAR_PROXY_BINARIES' docstring for why combining them
    # breaks (double-proxying a connection that itself is proxy-aware).
    uses_env_var_proxy = proxy is not None and binary in ENV_VAR_PROXY_BINARIES
    wrap_proxy = None if (proxy_flag_added or uses_env_var_proxy) else proxy

    if dry_run:
        if uses_env_var_proxy:
            display_cmd, via = cmd, f" (via HTTP_PROXY/HTTPS_PROXY env vars set to {proxy})"
        else:
            display_cmd, via = wrap_with_proxychains(cmd, wrap_proxy, proxy_dns=proxy_dns), ""
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=True,
            returncode=0,
            stdout=f"[DRY-RUN] would execute{via}: {' '.join(display_cmd)}",
            stderr="",
            duration_s=0.0,
        )

    if wrap_proxy is not None and not is_available(_PROXYCHAINS_BIN):
        return ToolResult(
            tool=tool_name,
            command=cmd,
            available=False,
            returncode=None,
            stdout="",
            stderr="",
            duration_s=0.0,
            skipped_reason=(
                f"proxy requested but '{_PROXYCHAINS_BIN}' not found on PATH. "
                f"Install with: sudo apt install {apt_hint(_PROXYCHAINS_BIN)}"
            ),
        )

    actual_cmd = wrap_with_proxychains(cmd, wrap_proxy, proxy_dns=proxy_dns)
    env = {**os.environ, **proxy_env_vars(proxy)} if uses_env_var_proxy else None

    start = time.monotonic()
    try:
        # Explicit stdin=DEVNULL, not just the default (inherit parent's stdin):
        # this runs inside a long-lived server's background worker thread, where
        # the parent's stdin isn't a real TTY. Some tools (e.g. subjack) use
        # os.Stdin.Stat() to decide "read targets from stdin instead of -w/-d",
        # and an inherited non-TTY stdin with nothing written to it makes them
        # silently process zero input rather than erroring -- DEVNULL is an
        # unambiguous "no stdin input" signal every tool interprets correctly.
        proc = subprocess.run(actual_cmd, capture_output=True, text=True, timeout=timeout,
                               stdin=subprocess.DEVNULL, env=env)
        return ToolResult(
            tool=tool_name,
            command=actual_cmd,
            available=True,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as exc:
        # CPython quirk: even with text=True, TimeoutExpired.stdout/stderr are
        # raw bytes (decoding happens later in the normal completion path,
        # which a timeout never reaches). Left undecoded, this crashes every
        # downstream str.join() the moment any tool actually times out.
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        return ToolResult(
            tool=tool_name,
            command=actual_cmd,
            available=True,
            returncode=None,
            stdout=stdout or "",
            stderr=f"Timed out after {timeout}s",
            duration_s=time.monotonic() - start,
        )
