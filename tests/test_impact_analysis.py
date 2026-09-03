from reconai.report import impact_analysis
from reconai.tools.base import ToolResult


def _result(tool: str, stdout: str, available: bool = True) -> ToolResult:
    return ToolResult(tool=tool, command=[tool], available=available, returncode=0,
                       stdout=stdout, stderr="", duration_s=0.0)


def test_analyze_returns_nothing_for_clean_results():
    results = [
        _result("nmap", "80/tcp   open   http       Apache httpd"),
        _result("security_headers", "No issues found."),
        _result("sqlmap", "all tested parameters do not appear to be injectable"),
    ]
    assert impact_analysis.analyze(results) == []


def test_detects_confirmed_sql_injection():
    results = [_result("sqlmap", "Parameter: id (GET)\nthe back-end DBMS is MySQL")]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "SQL injection" in findings[0].title


def test_detects_exposed_secret_scan_findings():
    results = [_result(
        "secret_scan",
        "[AWS Access Key] found in https://example.com/app.js: AKIAIOSFODNN7...\n"
        "[Exposed config file] https://example.com/.env is accessible and looks like real config content",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "2 exposed secret" in findings[0].title


def test_secret_scan_no_findings_produces_no_impact_entry():
    results = [_result("secret_scan", "Scanned 0 JS file(s) and 6 common config path(s).\n\n"
                                       "No secrets or exposed config files detected.")]
    assert impact_analysis.analyze(results) == []


def test_detects_verified_github_secret():
    results = [_result(
        "github_secrets",
        "GitHub org guess: 'example'. Scanned 1 repo(s).\n\n"
        '[example-infra] {"DetectorName":"AWS","Verified":true}',
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_unverified_github_secret_produces_no_impact_entry():
    results = [_result("github_secrets", "[example-web] no verified secrets found")]
    assert impact_analysis.analyze(results) == []


def test_detects_successful_zone_transfer():
    results = [_result("dns_axfr", "[CRITICAL] ZONE TRANSFER SUCCEEDED -- full DNS zone leaked by ns1:\n...")]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "AXFR" in findings[0].title
    assert findings[0].severity == "high"


def test_refused_zone_transfer_produces_no_impact_entry():
    results = [_result("dns_axfr", "no zone transfer (refused/failed) -- OK")]
    assert impact_analysis.analyze(results) == []


def test_detects_exposed_database_port():
    results = [_result("nmap", "3306/tcp open   mysql      MySQL 5.1.73-0ubuntu0.10.04.1")]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "MYSQL" in findings[0].title
    assert findings[0].severity == "high"


def test_web_only_nmap_output_produces_no_database_finding():
    results = [_result("nmap", "80/tcp   open   http       Apache httpd")]
    assert impact_analysis.analyze(results) == []


def test_detects_subdomain_takeover():
    results = [_result(
        "subjack",
        "[Not Vulnerable] www.example.com\n"
        "[VULNERABLE] old.example.com (CNAME: old.herokudns.com, Provider: Heroku)",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "takeover" in findings[0].title
    assert findings[0].severity == "high"


def test_detects_public_bucket():
    results = [_result(
        "bucket_enum",
        "[S3] https://example-backup.s3.amazonaws.com/ -- PUBLIC (listable)\n"
        "[GCS] https://storage.googleapis.com/example-assets/ -- exists, access denied (private)",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "1 publicly listable" in findings[0].title


def test_private_buckets_only_produce_no_impact_entry():
    results = [_result("bucket_enum", "[GCS] https://storage.googleapis.com/x/ -- exists, access denied (private)")]
    assert impact_analysis.analyze(results) == []


def test_detects_outdated_openssh():
    results = [_result("nmap", "22/tcp   open   ssh        OpenSSH 5.3p1 Debian 3ubuntu7.1 (Ubuntu Linux; protocol 2.0)")]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "outdated SSH" in findings[0].title
    assert "OpenSSH 5.3" in findings[0].evidence


def test_modern_openssh_produces_no_impact_entry():
    results = [_result("nmap", "22/tcp   open   ssh        OpenSSH 9.6p1 Ubuntu")]
    assert impact_analysis.analyze(results) == []


def test_detects_graphql_introspection():
    results = [_result(
        "graphql_probe",
        "Probed 6 candidate GraphQL endpoint(s).\n\n"
        "[GraphQL Introspection Enabled] https://example.com/graphql -- full schema is queryable",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_detects_clickjacking():
    results = [_result(
        "security_headers",
        "[Clickjacking] no X-Frame-Options header and no CSP frame-ancestors directive -- "
        "the page can be embedded in a hostile <iframe>",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "Clickjacking" in findings[0].title


def test_detects_reflected_xss():
    results = [_result(
        "injection_probe",
        "Probed 2 parameterized URL(s), 2 parameter(s) tested.\n\n"
        "[Reflected XSS] param 'q' on https://example.com/search?q=shoes -- "
        "injected marker reflected unescaped in response",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "XSS" in findings[0].title
    assert findings[0].severity == "high"


def test_no_xss_findings_produces_no_impact_entry():
    results = [_result("injection_probe", "Probed 2 parameterized URL(s), 2 parameter(s) tested.\n\n"
                                           "No injection signatures detected in the tested parameters.")]
    assert impact_analysis.analyze(results) == []


def test_detects_cors_misconfiguration():
    results = [_result(
        "cors_scan",
        "[CORS Misconfiguration] Origin 'https://evil.example' reflected verbatim in "
        "Access-Control-Allow-Origin (with Access-Control-Allow-Credentials: true)",
    )]
    findings = impact_analysis.analyze(results)
    assert len(findings) == 1
    assert "CORS" in findings[0].title


def test_unavailable_tool_result_is_ignored_not_crashed_on():
    results = [
        ToolResult(tool="nmap", command=["nmap"], available=False, returncode=None,
                   stdout="", stderr="", duration_s=0.0, skipped_reason="nmap not found"),
        ToolResult(tool="sqlmap", command=["sqlmap"], available=False, returncode=None,
                   stdout="", stderr="", duration_s=0.0, skipped_reason="no parameterized URLs"),
    ]
    assert impact_analysis.analyze(results) == []


def test_findings_sorted_by_severity_critical_first():
    results = [
        _result("security_headers", "[Clickjacking] no X-Frame-Options header"),  # medium
        _result("sqlmap", "the back-end DBMS is MySQL"),  # critical
        _result("nmap", "3306/tcp open   mysql      MySQL 5.1"),  # high
    ]
    findings = impact_analysis.analyze(results)
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: impact_analysis._SEVERITY_ORDER[s])
    assert severities[0] == "critical"


def test_render_markdown_empty_for_no_findings():
    assert impact_analysis.render_markdown([]) == ""


def test_detects_nuclei_findings_grouped_by_severity():
    results = [_result(
        "nuclei",
        "[ssh-diffie-hellman-logjam] [javascript] [low] example.com:22\n"
        "[exposed-panel] [http] [high] https://example.com/admin\n",
    )]
    findings = impact_analysis.analyze(results)
    severities = {f.severity for f in findings}
    assert "high" in severities and "low" in severities
    assert any("nuclei template match" in f.title for f in findings)


def test_nuclei_line_without_a_recognized_severity_is_ignored():
    results = [_result("nuclei", "[info-only-template] [http] [info] example.com\n")]
    assert impact_analysis.analyze(results) == []


def test_detects_weak_auth_findings():
    results = [_result(
        "auth_audit",
        "Probed 5 candidate authentication endpoint(s).\n\n"
        "[Cleartext Credential Submission] http://example.com/login -- password form served over "
        "plain HTTP\n"
        "[Weak Password Policy] http://example.com/register -- password field caps input at 8 "
        "characters\n"
        "[Missing CSRF Protection] http://example.com/login -- no hidden field matching a common "
        "CSRF-token naming pattern found\n",
    )]
    findings = impact_analysis.analyze(results)
    titles = " ".join(f.title for f in findings)
    severities = [f.severity for f in findings]
    assert "plain HTTP" in titles or "cleartext" in titles.lower() or "password length" in titles.lower()
    assert "critical" in severities  # cleartext credential submission
    assert severities.count("medium") >= 2  # weak password policy + missing CSRF


def test_no_auth_findings_produces_no_impact_entry():
    results = [_result("auth_audit", "Probed 5 candidate authentication endpoint(s).\n\n"
                                      "No login/registration forms found, or every form found "
                                      "looked properly hardened.")]
    assert impact_analysis.analyze(results) == []


def test_detects_privacy_exposure_findings():
    results = [_result(
        "privacy_scan",
        "[Tracking Without Consent Signal] tracker script(s) detected (gtag() with no "
        "cookie-consent/CMP marker found in the same response\n"
        "[Weak Referrer Policy] Referrer-Policy header is missing\n"
        "[Missing Permissions-Policy] no Permissions-Policy/Feature-Policy header\n",
    )]
    findings = impact_analysis.analyze(results)
    severities = [f.severity for f in findings]
    assert "medium" in severities  # tracking without consent
    assert "low" in severities  # header gaps


def test_clean_privacy_scan_produces_no_impact_entry():
    results = [_result("privacy_scan", "No tracking-without-consent signals or missing "
                                        "privacy-related headers detected.")]
    assert impact_analysis.analyze(results) == []


def test_compute_score_no_findings_is_perfect_a():
    score, grade = impact_analysis.compute_score([])
    assert score == 100
    assert grade == "A"


def test_compute_score_one_critical_drops_to_b():
    finding = impact_analysis.ImpactFinding(title="x", severity="critical", evidence="e", impact="i", recommendation="r")
    score, grade = impact_analysis.compute_score([finding])
    assert score == 75
    assert grade == "B"


def test_compute_score_floors_at_zero_and_grades_f():
    findings = [impact_analysis.ImpactFinding(title="x", severity="critical", evidence="e", impact="i", recommendation="r")
                for _ in range(6)]
    score, grade = impact_analysis.compute_score(findings)
    assert score == 0
    assert grade == "F"


def test_render_markdown_includes_all_four_fields_per_finding():
    finding = impact_analysis.ImpactFinding(
        title="Example finding", severity="high", evidence="tool: some evidence",
        impact="what an attacker could do", recommendation="what to fix",
    )
    rendered = impact_analysis.render_markdown([finding])
    assert "## Potential Impact Analysis" in rendered
    assert "[HIGH] Example finding" in rendered
    assert "**Evidence:** tool: some evidence" in rendered
    assert "**Potential impact if exploited:** what an attacker could do" in rendered
    assert "**Recommendation:** what to fix" in rendered
