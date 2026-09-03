from __future__ import annotations

import re
from dataclasses import dataclass

from ..tools.base import ToolResult

# Deterministic, rule-based "what could an attacker actually do with this"
# narrative generator -- NOT an exploitation feature. Nothing in this module
# sends a single byte to the target; it only reads the ToolResults the
# pipeline already collected and writes a risk-prioritized explanation.
# Kept rule-based rather than LLM-driven so it's a) testable without a live
# backend, b) works identically for every backend including --dry-run/mock,
# and c) can't hallucinate a finding that isn't actually backed by evidence
# in the raw tool output -- each detector only fires on an explicit marker
# already present in a specific tool's real output format.

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SCORE_PENALTY = {"critical": 25, "high": 15, "medium": 7, "low": 3}
_GRADE_CUTOFFS = (("A", 90), ("B", 75), ("C", 60), ("D", 40))

_DB_SERVICES = {"mysql", "postgresql", "mongodb", "redis", "mssql", "oracle"}
_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$", re.MULTILINE)
# OpenSSH's own banner format, e.g. "OpenSSH 5.3p1 Debian 3ubuntu7.1 (...)"
_OPENSSH_VERSION_RE = re.compile(r"OpenSSH_?\s*(\d+)\.(\d+)")
# Below this major version is a decade-plus old regardless of what "today" is.
_OPENSSH_OUTDATED_MAJOR = 7
# nuclei -silent output, e.g. "[ssh-diffie-hellman-logjam] [javascript] [low] host:22"
# -- template-id, protocol, severity, matched-at. Confirmed real format from live scans.
_NUCLEI_LINE_RE = re.compile(r"^\[([^\]]+)\]\s*\[[^\]]+\]\s*\[(critical|high|medium|low)\]\s*(\S+)", re.IGNORECASE)


@dataclass
class ImpactFinding:
    title: str
    severity: str  # "critical" | "high" | "medium" | "low"
    evidence: str
    impact: str
    recommendation: str


def _tool(results: list[ToolResult], name: str) -> ToolResult | None:
    return next((r for r in results if r.tool == name), None)


def _detect_sql_injection(results: list[ToolResult]) -> list[ImpactFinding]:
    sqlmap = _tool(results, "sqlmap")
    if not sqlmap or not sqlmap.available or "the back-end DBMS is" not in sqlmap.stdout:
        return []
    evidence = next((l for l in sqlmap.stdout.splitlines() if "the back-end DBMS is" in l), "sqlmap")
    return [ImpactFinding(
        title="Confirmed SQL injection",
        severity="critical",
        evidence=f"sqlmap: {evidence.strip()}",
        impact=("sqlmap confirmed it can inject SQL through this parameter. Depending on the "
                "database account's privileges this typically allows reading any table -- "
                "including other users' data or stored credentials -- and on an over-privileged "
                "account can extend to writing files or, in some configurations, command "
                "execution on the database server."),
        recommendation="Switch this query to parameterized statements/prepared queries -- this is a "
                        "priority-one fix, not a hardening suggestion.",
    )]


def _detect_exposed_secrets(results: list[ToolResult]) -> list[ImpactFinding]:
    findings = []
    secret_scan = _tool(results, "secret_scan")
    if secret_scan and secret_scan.available:
        lines = [l for l in secret_scan.stdout.splitlines()
                 if l.startswith("[") and ("found in" in l or "is accessible" in l)]
        if lines:
            shown = "; ".join(lines[:3]) + (f" (+{len(lines) - 3} more)" if len(lines) > 3 else "")
            findings.append(ImpactFinding(
                title=f"{len(lines)} exposed secret(s)/config file(s) reachable on the live site",
                severity="critical",
                evidence=f"secret_scan: {shown}",
                impact=("These values are directly usable by anyone who requests the URL -- no "
                        "exploitation needed beyond fetching the page. Depending on what they grant "
                        "access to (cloud storage, a database, a third-party API), this can mean "
                        "immediate, direct account or data compromise."),
                recommendation="Rotate every exposed credential immediately, then remove the exposing "
                                "file/bundle from the deployed site.",
            ))
    github_secrets = _tool(results, "github_secrets")
    if github_secrets and github_secrets.available and '"Verified":true' in github_secrets.stdout:
        findings.append(ImpactFinding(
            title="Verified secret(s) committed to a linked GitHub repository",
            severity="critical",
            evidence="github_secrets: at least one trufflehog-verified credential found",
            impact=("\"Verified\" means the credential was actually confirmed live against the "
                    "provider, not just pattern-matched -- this is a working credential sitting in "
                    "git history, usable by anyone who can read the repo."),
            recommendation="Rotate the credential immediately and purge it from git history -- "
                            "rotation alone isn't enough if the repo is public, since history remains.",
        ))
    return findings


def _detect_zone_transfer(results: list[ToolResult]) -> list[ImpactFinding]:
    dns_axfr = _tool(results, "dns_axfr")
    if not dns_axfr or not dns_axfr.available or "ZONE TRANSFER SUCCEEDED" not in dns_axfr.stdout:
        return []
    return [ImpactFinding(
        title="DNS zone transfer (AXFR) succeeded",
        severity="high",
        evidence="dns_axfr: a nameserver allowed an unauthenticated AXFR",
        impact=("The complete DNS zone -- every subdomain and internal hostname the organization "
                "has ever recorded there, including ones never meant to be public (staging, admin, "
                "internal tooling) -- was handed over with no authentication. That's a full map of "
                "internal naming and infrastructure for free, no brute-forcing required."),
        recommendation="Restrict zone transfers to designated secondary nameservers only.",
    )]


def _detect_exposed_databases(results: list[ToolResult]) -> list[ImpactFinding]:
    nmap = _tool(results, "nmap")
    if not nmap or not nmap.available:
        return []
    findings = []
    for port, service, version in _NMAP_PORT_RE.findall(nmap.stdout):
        if service.lower() not in _DB_SERVICES:
            continue
        findings.append(ImpactFinding(
            title=f"{service.upper()} database directly reachable on port {port}",
            severity="high",
            evidence=f"nmap: {port}/tcp open {service} {version}".strip(),
            impact=("A database service is reachable from the internet, not just from the "
                    "application server that's supposed to be its only client. If credentials are "
                    "weak, default, or reused anywhere else, an attacker can authenticate directly "
                    "and read, modify, or exfiltrate the underlying data without ever touching the "
                    "web application."),
            recommendation="Firewall this port to the application server's IP only (or put it behind "
                            "a VPN/bastion) -- databases should never be reachable directly from the "
                            "public internet.",
        ))
    return findings


def _detect_subdomain_takeover(results: list[ToolResult]) -> list[ImpactFinding]:
    subjack = _tool(results, "subjack")
    if not subjack or not subjack.available:
        return []
    lines = [l for l in subjack.stdout.splitlines() if l.startswith("[VULNERABLE]")]
    if not lines:
        return []
    return [ImpactFinding(
        title=f"{len(lines)} subdomain(s) vulnerable to takeover",
        severity="high",
        evidence="; ".join(lines),
        impact=("These subdomains have a DNS record (usually a CNAME) pointing at a cloud/SaaS "
                "resource that's since been deleted or never claimed. An attacker can register that "
                "resource themselves and have it start serving their own content from the "
                "organization's own subdomain -- useful for phishing, cookie/session theft if the "
                "parent domain sets broad cookies, or reputational damage."),
        recommendation="Remove the dangling DNS record, or claim/reclaim the underlying resource.",
    )]


def _detect_public_bucket(results: list[ToolResult]) -> list[ImpactFinding]:
    bucket_enum = _tool(results, "bucket_enum")
    if not bucket_enum or not bucket_enum.available:
        return []
    lines = [l for l in bucket_enum.stdout.splitlines() if "PUBLIC (listable)" in l]
    if not lines:
        return []
    return [ImpactFinding(
        title=f"{len(lines)} publicly listable cloud storage bucket(s)",
        severity="high",
        evidence="; ".join(lines),
        impact=("Anyone can list -- and, depending on object-level ACLs, very likely download -- "
                "the full contents of these buckets with no authentication. If they contain backups, "
                "user uploads, or internal files, this is a direct data exposure that needs no "
                "exploit at all, just a request."),
        recommendation="Set bucket ACLs to private and audit what may already have been scraped by "
                        "scanners or indexed by search engines while it was public.",
    )]


def _detect_outdated_ssh(results: list[ToolResult]) -> list[ImpactFinding]:
    nmap = _tool(results, "nmap")
    if not nmap or not nmap.available:
        return []
    match = _OPENSSH_VERSION_RE.search(nmap.stdout)
    if not match or int(match.group(1)) >= _OPENSSH_OUTDATED_MAJOR:
        return []
    return [ImpactFinding(
        title=f"Severely outdated SSH server ({match.group(0)})",
        severity="high",
        evidence=f"nmap: {match.group(0)} detected on port 22",
        impact=("This SSH version predates a decade or more of security patches. Beyond any "
                "SSH-specific weaknesses, a version this old is a strong signal the underlying OS "
                "itself is past end-of-life -- an attacker who obtains any valid credentials "
                "(reuse, phishing, a weak password) would then be operating on a kernel/userland "
                "with a large, unpatched surface for local privilege escalation."),
        recommendation="Upgrade the host OS to a supported release; this resolves the SSH issue and "
                        "the broader unpatched-OS risk together.",
    )]


def _detect_nuclei_findings(results: list[ToolResult]) -> list[ImpactFinding]:
    nuclei = _tool(results, "nuclei")
    if not nuclei or not nuclei.available:
        return []
    by_severity: dict[str, list[str]] = {}
    for line in nuclei.stdout.splitlines():
        match = _NUCLEI_LINE_RE.match(line.strip())
        if not match:
            continue
        template_id, severity, matched_at = match.group(1), match.group(2).lower(), match.group(3)
        by_severity.setdefault(severity, []).append(f"{template_id} ({matched_at})")
    findings = []
    for severity, lines in by_severity.items():
        shown = ", ".join(lines[:3]) + (f" (+{len(lines) - 3} more)" if len(lines) > 3 else "")
        findings.append(ImpactFinding(
            title=f"{len(lines)} {severity}-severity nuclei template match(es)",
            severity=severity,
            evidence=f"nuclei: {shown}",
            impact=("nuclei matched known CVE/misconfiguration signatures against this target. Each "
                    "template encodes a previously-published, often actively-exploited weakness -- "
                    "unlike a heuristic guess, this is pattern-matched against real, cataloged threats, "
                    "so these matches are worth prioritizing over generic findings of the same severity."),
            recommendation="Review each matched template ID against its nuclei-templates source for the "
                            "specific fix -- the template name (shown above) maps directly to a public "
                            "advisory or CVE in most cases.",
        ))
    return findings


def _detect_graphql_introspection(results: list[ToolResult]) -> list[ImpactFinding]:
    graphql_probe = _tool(results, "graphql_probe")
    if not graphql_probe or not graphql_probe.available:
        return []
    if "[GraphQL Introspection Enabled]" not in graphql_probe.stdout:
        return []
    evidence = next((l for l in graphql_probe.stdout.splitlines()
                      if "[GraphQL Introspection Enabled]" in l), "graphql_probe")
    return [ImpactFinding(
        title="GraphQL introspection enabled",
        severity="medium",
        evidence=evidence,
        impact=("The full API schema -- every type, field, and mutation, including ones with no UI "
                "pathway to reach them -- is queryable by anyone. This hands an attacker a complete "
                "map of the API surface, including internal/admin-only mutations they wouldn't "
                "otherwise know exist, which dramatically speeds up finding a real authorization or "
                "injection flaw."),
        recommendation="Disable introspection in production -- most GraphQL frameworks have a "
                        "single config flag for this.",
    )]


def _detect_clickjacking(results: list[ToolResult]) -> list[ImpactFinding]:
    security_headers = _tool(results, "security_headers")
    if not security_headers or not security_headers.available:
        return []
    if "[Clickjacking]" not in security_headers.stdout:
        return []
    return [ImpactFinding(
        title="Clickjacking (no frame protection)",
        severity="medium",
        evidence="security_headers: no X-Frame-Options / CSP frame-ancestors",
        impact=("The site can be embedded in a hidden or disguised <iframe> on an attacker-"
                "controlled page. Combined with any sensitive action a logged-in user can trigger "
                "with a click (changing a setting, submitting a form), an attacker can trick a "
                "victim into performing that action without realizing it."),
        recommendation="Set X-Frame-Options: DENY (or SAMEORIGIN if the site frames itself) or a CSP "
                        "frame-ancestors directive.",
    )]


def _detect_reflected_xss(results: list[ToolResult]) -> list[ImpactFinding]:
    injection_probe = _tool(results, "injection_probe")
    if not injection_probe or not injection_probe.available:
        return []
    lines = [l for l in injection_probe.stdout.splitlines() if l.startswith("[Reflected XSS]")]
    if not lines:
        return []
    shown = "; ".join(lines[:3]) + (f" (+{len(lines) - 3} more)" if len(lines) > 3 else "")
    return [ImpactFinding(
        title=f"{len(lines)} reflected XSS parameter(s) confirmed",
        severity="high",
        evidence=f"injection_probe: {shown}",
        impact=("User-controlled input is rendered back into the page without escaping. An "
                "attacker who gets a victim to click a crafted link can run arbitrary JavaScript "
                "in that victim's browser session on this site -- typically enough to steal "
                "session cookies/tokens, perform actions as the victim, or redirect them to a "
                "phishing page, all while the URL still appears to point at the legitimate site."),
        recommendation="HTML-encode all user-controlled output at render time (or adopt a "
                        "templating engine that does this by default); add a Content-Security-Policy "
                        "as defense in depth.",
    )]


def _detect_cors_misconfig(results: list[ToolResult]) -> list[ImpactFinding]:
    cors_scan = _tool(results, "cors_scan")
    if not cors_scan or not cors_scan.available:
        return []
    if "[CORS Misconfiguration]" not in cors_scan.stdout:
        return []
    evidence = next((l for l in cors_scan.stdout.splitlines()
                      if "[CORS Misconfiguration]" in l), "cors_scan")
    return [ImpactFinding(
        title="CORS misconfiguration",
        severity="medium",
        evidence=evidence,
        impact=("A malicious website can make authenticated cross-origin requests to this site on a "
                "victim's behalf and read the response. If any endpoint returns sensitive per-user "
                "data, an attacker-controlled page visited by a logged-in victim can silently "
                "exfiltrate it in the background."),
        recommendation="Restrict Access-Control-Allow-Origin to a fixed allowlist of trusted origins "
                        "-- never reflect an arbitrary Origin header, especially alongside "
                        "Access-Control-Allow-Credentials.",
    )]


def _lines_with_tag(stdout: str, tag: str) -> list[str]:
    return [l for l in stdout.splitlines() if l.startswith(tag)]


def _detect_weak_auth(results: list[ToolResult]) -> list[ImpactFinding]:
    auth_audit = _tool(results, "auth_audit")
    if not auth_audit or not auth_audit.available:
        return []
    findings = []

    cleartext = _lines_with_tag(auth_audit.stdout, "[Cleartext Credential Submission]")
    if cleartext:
        findings.append(ImpactFinding(
            title=f"{len(cleartext)} login/registration form(s) submit credentials over plain HTTP",
            severity="critical",
            evidence=f"auth_audit: {cleartext[0]}" + (f" (+{len(cleartext) - 1} more)" if len(cleartext) > 1 else ""),
            impact=("Usernames and passwords are sent unencrypted. Anyone positioned on the network "
                    "path between a user and the server -- public Wi-Fi, a compromised router, an "
                    "ISP -- can read credentials directly off the wire as they're typed and submitted."),
            recommendation="Serve every authentication form over HTTPS, and redirect all HTTP traffic "
                            "to HTTPS site-wide.",
        ))

    weak_policy = _lines_with_tag(auth_audit.stdout, "[Weak Password Policy]")
    if weak_policy:
        findings.append(ImpactFinding(
            title=f"{len(weak_policy)} form(s) cap password length below a reasonable minimum",
            severity="medium",
            evidence=f"auth_audit: {weak_policy[0]}" + (f" (+{len(weak_policy) - 1} more)" if len(weak_policy) > 1 else ""),
            impact=("A low maximum password length meaningfully weakens resistance to offline "
                    "brute-force/credential-stuffing attacks, and is often a symptom of outdated, "
                    "length-sensitive password storage rather than a simple validation choice."),
            recommendation="Remove the artificial cap (allow at least 64 characters) and confirm "
                            "passwords are stored with a modern salted hash (bcrypt/Argon2).",
        ))

    missing_csrf = _lines_with_tag(auth_audit.stdout, "[Missing CSRF Protection]")
    if missing_csrf:
        findings.append(ImpactFinding(
            title=f"{len(missing_csrf)} form(s) show no CSRF-token naming pattern",
            severity="medium",
            evidence=f"auth_audit: {missing_csrf[0]}" + (f" (+{len(missing_csrf) - 1} more)" if len(missing_csrf) > 1 else ""),
            impact=("Without CSRF protection, an attacker can potentially trick a logged-in user's "
                    "browser into submitting this form without their knowledge. Heuristic result -- "
                    "verify manually before treating as confirmed, since CSRF defenses aren't always "
                    "implemented as a conventionally-named hidden field."),
            recommendation="Add a per-session CSRF token to every state-changing form, validated "
                            "server-side on submission.",
        ))

    return findings


def _detect_privacy_exposure(results: list[ToolResult]) -> list[ImpactFinding]:
    privacy_scan = _tool(results, "privacy_scan")
    if not privacy_scan or not privacy_scan.available:
        return []
    findings = []

    tracking = _lines_with_tag(privacy_scan.stdout, "[Tracking Without Consent Signal]")
    if tracking:
        findings.append(ImpactFinding(
            title="Tracking scripts detected with no visible consent mechanism",
            severity="medium",
            evidence=f"privacy_scan: {tracking[0]}",
            impact=("Analytics/advertising trackers appear to load unconditionally. Depending on the "
                    "site's audience and jurisdiction, collecting tracking data before obtaining "
                    "consent can be a real compliance exposure (GDPR, and similar regional laws), on "
                    "top of the direct privacy impact to visitors."),
            recommendation="Gate tracking scripts behind a consent-management platform so they only "
                            "load after a visitor opts in.",
        ))

    header_issues = _lines_with_tag(privacy_scan.stdout, "[Weak Referrer Policy]") + \
        _lines_with_tag(privacy_scan.stdout, "[Missing Permissions-Policy]")
    if header_issues:
        findings.append(ImpactFinding(
            title=f"{len(header_issues)} privacy-related header gap(s)",
            severity="low",
            evidence=f"privacy_scan: {'; '.join(header_issues)}",
            impact=("A weak or missing Referrer-Policy can leak full URLs (including sensitive query "
                    "parameters) to third parties via outbound links; a missing Permissions-Policy "
                    "leaves camera/microphone/geolocation access to embedded content unrestricted by "
                    "default. Both are low-severity in isolation but cheap to close."),
            recommendation="Set a strict Referrer-Policy (e.g. strict-origin-when-cross-origin) and a "
                            "Permissions-Policy that denies sensor access by default.",
        ))

    return findings


_DETECTORS = (
    _detect_sql_injection,
    _detect_reflected_xss,
    _detect_exposed_secrets,
    _detect_zone_transfer,
    _detect_exposed_databases,
    _detect_subdomain_takeover,
    _detect_public_bucket,
    _detect_outdated_ssh,
    _detect_nuclei_findings,
    _detect_graphql_introspection,
    _detect_clickjacking,
    _detect_cors_misconfig,
    _detect_weak_auth,
    _detect_privacy_exposure,
)


def analyze(results: list[ToolResult]) -> list[ImpactFinding]:
    findings: list[ImpactFinding] = []
    for detector in _DETECTORS:
        findings.extend(detector(results))
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return findings


def compute_score(findings: list[ImpactFinding]) -> tuple[int, str]:
    """A simple, explainable 0-100 "security awareness" score -- start at 100,
    subtract a fixed penalty per finding by severity, floor at 0. Deliberately
    not a weighted/statistical model: the point is a number a non-technical
    reader can sanity-check against the finding list right next to it, not a
    black-box risk metric."""
    score = 100
    for finding in findings:
        score -= _SCORE_PENALTY.get(finding.severity, 0)
    score = max(0, score)
    grade = next((g for g, cutoff in _GRADE_CUTOFFS if score >= cutoff), "F")
    return score, grade


def render_markdown(findings: list[ImpactFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "## Potential Impact Analysis",
        "",
        "_Theoretical impact if each finding below were actively exploited -- written risk "
        "analysis only. Nothing in this section was executed against the target; see the tool "
        "that generated the evidence for what was actually run._",
        "",
    ]
    for finding in findings:
        lines += [
            f"### [{finding.severity.upper()}] {finding.title}",
            f"**Evidence:** {finding.evidence}",
            f"**Potential impact if exploited:** {finding.impact}",
            f"**Recommendation:** {finding.recommendation}",
            "",
        ]
    return "\n".join(lines)
