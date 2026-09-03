from __future__ import annotations

from urllib.parse import quote_plus

from .base import ToolResult
from .mock_data import MOCK_OUTPUTS

NAME = "google_dorks"

# Curated, generic dork categories -- each targets a class of exposure that
# only a search engine's index can reveal (things that were public and
# crawled at some point), distinct from what the rest of the pipeline
# already checks by probing the live site directly (secret_scan,
# security_headers, etc.). Not executed automatically: scraping Google
# search results directly gets CAPTCHA'd almost immediately, especially from
# a Tor exit IP, and there's no ToS-compliant free API for arbitrary dork
# queries -- these are meant to be opened by hand in a browser.
_CATEGORIES = (
    ("Directory listings", 'intitle:"index of"'),
    ("Exposed SQL/database dumps", "filetype:sql"),
    ("Exposed environment/config files", "(filetype:env OR filetype:ini OR filetype:conf OR filetype:yml)"),
    ("Exposed backup files", "(filetype:bak OR filetype:old OR filetype:backup OR filetype:swp)"),
    ("Exposed log files", "filetype:log"),
    ("Admin/login panels indexed", "(inurl:admin OR inurl:login OR inurl:signin OR inurl:cpanel)"),
    ("Exposed source control", "(inurl:.git OR inurl:.svn OR inurl:.env)"),
    ("phpinfo() disclosure", 'intitle:"phpinfo()"'),
    ("Error messages / stack traces", '("SQL syntax" OR "Warning: mysql_" OR "Fatal error" OR "stack trace")'),
    ("Sensitive documents", "(filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx OR filetype:pdf) "
                             "(confidential OR internal OR password)"),
    ("Test/staging/dev environments indexed", "(inurl:test OR inurl:dev OR inurl:staging OR inurl:uat)"),
    ("Possible credential/key exposure", '(intext:"BEGIN RSA PRIVATE KEY" OR intext:"api_key" '
                                          'OR intext:"aws_secret_access_key")'),
)


def build_dorks(domain: str) -> list[tuple[str, str]]:
    """Returns (label, query) pairs. A trailing "subdomains indexed by
    Google" entry is added separately since its query shape (site:*.domain)
    differs from the "site:domain <filter>" pattern of everything else --
    it's a useful cross-check against the passive-DNS-derived subdomain list
    (Google's index sometimes has names crt.sh/subfinder don't)."""
    dorks = [(label, f"site:{domain} {filt}") for label, filt in _CATEGORIES]
    dorks.append(("Subdomains indexed by Google (cross-check against passive DNS)",
                   f"site:*.{domain} -site:www.{domain}"))
    return dorks


def _search_url(query: str) -> str:
    return f"https://www.google.com/search?q={quote_plus(query)}"


def run(target: str, dry_run: bool = False, mock: bool = False, proxy: str | None = None) -> ToolResult:
    cmd = ["reconai-google-dorks", f"--domain={target}"]

    if mock:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=MOCK_OUTPUTS[NAME], stderr="", duration_s=0.0, mocked=True)

    dorks = build_dorks(target)

    if dry_run:
        return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                           stdout=f"[DRY-RUN] would generate {len(dorks)} Google dork queries for {target}",
                           stderr="", duration_s=0.0)

    lines = [
        f"Generated {len(dorks)} Google dork queries for manual review.",
        "Not executed automatically -- automating Google searches risks CAPTCHA/ToS issues, "
        "especially from a Tor exit node. Open these yourself in a browser.",
        "",
    ]
    for label, query in dorks:
        lines.append(f"### {label}")
        lines.append(query)
        lines.append(_search_url(query))
        lines.append("")

    return ToolResult(tool=NAME, command=cmd, available=True, returncode=0,
                       stdout="\n".join(lines), stderr="", duration_s=0.0)
