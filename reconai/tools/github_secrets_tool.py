from __future__ import annotations

import tempfile
import time
from pathlib import Path

import httpx  # the pip HTTP client library (requirements.txt)

from .base import (
    _TRUFFLEHOG_BIN,
    ProxyUnavailable,
    ToolResult,
    apt_hint,
    guess_org_name,
    httpx_client,
    is_available,
    run_command,
)
from .mock_data import MOCK_OUTPUTS

NAME = "github_secrets"

_MAX_REPOS = 3
_CLONE_TIMEOUT = 60
_SCAN_TIMEOUT = 120
# Below this length, a guessed org/user name has a materially higher chance
# of coincidentally matching an unrelated real GitHub account rather than the
# actual target -- verified for real: "csk" (guessed for www.csk.gov.in)
# turned out to be a genuine, unrelated GitHub *user* account (3-letter
# usernames are highly contested and get claimed early by unrelated people).
# Unlike bucket_enum's read-only existence check, this tool clones and scans
# full repo contents -- cloning the wrong org/user is a real
# authorization-boundary violation, not just a noisy result, so this skips
# rather than guesses past the point of reasonable confidence.
_MIN_ORG_NAME_LENGTH = 4


def _guess_org_name(target: str) -> str:
    return guess_org_name(target)


def _find_org_repos(org: str, proxy: str | None = None) -> list[str] | None:
    """Clone URLs for the most-recently-pushed public repos under the guessed
    name, or None if nothing matches. Tries the /orgs/ endpoint first (formal
    GitHub Organizations), then falls back to /users/ -- many companies,
    especially smaller ones, publish under a personal-style user account
    rather than a registered Organization, and GitHub's API treats these as
    distinct resources with no automatic fallback between them."""
    try:
        with httpx_client(proxy=proxy, timeout=10.0) as client:
            for kind in ("orgs", "users"):
                r = client.get(
                    f"https://api.github.com/{kind}/{org}/repos",
                    params={"sort": "pushed", "per_page": _MAX_REPOS},
                )
                if r.status_code == 404:
                    continue
                r.raise_for_status()
                repos = r.json()
                if repos:
                    return [repo["clone_url"] for repo in repos[:_MAX_REPOS]]
    except (httpx.HTTPError, ValueError):
        return None
    return None


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    org = _guess_org_name(target)
    cmd = ["reconai-github-secrets", f"--org-guess={org}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    if not is_available(_TRUFFLEHOG_BIN):
        return ToolResult(
            tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
            duration_s=0.0, skipped_reason=f"'trufflehog' not found. Install with: {apt_hint(_TRUFFLEHOG_BIN)}",
        )
    if not is_available("git"):
        return ToolResult(
            tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
            duration_s=0.0, skipped_reason=f"'git' not found on PATH. Install with: sudo apt install {apt_hint('git')}",
        )

    if len(org) < _MIN_ORG_NAME_LENGTH:
        return ToolResult(
            tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
            duration_s=0.0,
            skipped_reason=(
                f"guessed org/user name '{org}' is too short ({len(org)} chars) to clone with "
                "reasonable confidence -- short names are far more likely to coincidentally match "
                "an unrelated real GitHub account than the actual target. Skipped rather than "
                "risk cloning and scanning someone else's repos."
            ),
        )

    if dry_run:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=(f"[DRY-RUN] would look up GitHub org '{org}', clone up to {_MAX_REPOS} repos "
                    "(shallow, latest commit only), and scan each with trufflehog --only-verified"),
            stderr="", duration_s=0.0,
        )

    start = time.monotonic()
    try:
        clone_urls = _find_org_repos(org, proxy)
    except ProxyUnavailable as exc:
        return ToolResult(tool=NAME, command=cmd, available=False, returncode=None, stdout="", stderr="",
                           duration_s=time.monotonic() - start, skipped_reason=str(exc))
    if not clone_urls:
        return ToolResult(
            tool=NAME, command=cmd, available=True, returncode=0,
            stdout=f"No public GitHub org found matching guessed name '{org}'.",
            stderr="", duration_s=time.monotonic() - start,
        )

    findings = []
    with tempfile.TemporaryDirectory(prefix="reconai-ghsecrets-") as tmp:
        for clone_url in clone_urls:
            repo_name = clone_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            repo_path = Path(tmp) / repo_name

            clone_result = run_command(
                "git", ["git", "clone", "--depth", "1", "--quiet", clone_url, str(repo_path)],
                timeout=_CLONE_TIMEOUT, proxy=proxy,
            )
            if not clone_result.available or clone_result.returncode != 0:
                findings.append(f"[{repo_name}] clone failed, skipped")
                continue

            # --only-verified: trufflehog performs a live, read-only check (e.g.
            # a minimal-privilege identity call) to confirm a found secret is a
            # real, active credential rather than a random high-entropy string
            # that merely looks like one. This dramatically cuts false
            # positives but does mean a genuine hit makes one confirmatory call
            # to the credential's own provider (AWS/GCP/etc), not to the target.
            scan_result = run_command(
                _TRUFFLEHOG_BIN,
                [_TRUFFLEHOG_BIN, "filesystem", str(repo_path), "--only-verified", "--json"],
                timeout=_SCAN_TIMEOUT, proxy=proxy,
            )
            if scan_result.stdout.strip():
                findings.append(f"[{repo_name}]\n{scan_result.stdout.strip()}")
            else:
                findings.append(f"[{repo_name}] no verified secrets found")

    duration = time.monotonic() - start
    header = f"GitHub org guess: '{org}'. Scanned {len(clone_urls)} repo(s) (shallow clone, latest commit only)."
    stdout = header + "\n\n" + "\n\n".join(findings)
    return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                       stdout=stdout, stderr="", duration_s=duration)
