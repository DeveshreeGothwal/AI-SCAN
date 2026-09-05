import os
from unittest.mock import patch

import httpx

from reconai.tools import (
    crtsh_tool,
    cve_correlate_tool,
    dns_axfr_tool,
    ffuf_tool,
    getjs_tool,
    github_secrets_tool,
    google_dorks_tool,
    httpx_tool,
    linkfinder_tool,
    nuclei_tool,
    sqlmap_tool,
    subfinder_tool,
    subjack_tool,
    testssl_tool,
    theharvester_tool,
    wafw00f_tool,
    waybackurls_tool,
)
from reconai.tools.base import GO_BIN, LINKFINDER_PYTHON


def test_parse_subdomains_splits_and_strips_blank_lines():
    stdout = "www.example.com\napi.example.com\n\n  \nstaging.example.com\n"
    assert subfinder_tool.parse_subdomains(stdout) == [
        "www.example.com", "api.example.com", "staging.example.com",
    ]


def test_parse_subdomains_empty_output():
    assert subfinder_tool.parse_subdomains("") == []


def test_httpx_dry_run_uses_real_binary_path_not_apt_httpx():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "httpx")):
        result = httpx_tool.run(["a.example.com", "b.example.com"], dry_run=True)
    assert result.command[0] == str(GO_BIN / "httpx")
    assert "-l" in result.command


def test_httpx_writes_subdomains_to_temp_file_for_real_run(tmp_path):
    fake_bin = tmp_path / "httpx"
    fake_bin.write_text("#!/bin/sh\ncat \"$2\"\n")
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.httpx_tool._HTTPX_BIN", str(fake_bin)):
        result = httpx_tool.run(["a.example.com", "b.example.com"], dry_run=False)
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout


def test_nuclei_dry_run_command():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/nuclei"):
        result = nuclei_tool.run("https://example.com", dry_run=True)
    assert result.command == ["nuclei", "-u", "https://example.com", "-silent", "-severity", "low,medium,high,critical"]


def test_ffuf_dry_run_command_includes_fuzz_keyword():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/ffuf"):
        result = ffuf_tool.run("https://example.com", dry_run=True)
    assert "https://example.com/FUZZ" in result.command


def test_wafw00f_dry_run_command():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/wafw00f"):
        result = wafw00f_tool.run("https://example.com", dry_run=True)
    assert result.command == ["wafw00f", "https://example.com"]


def test_testssl_targets_host_and_port():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/testssl"):
        result = testssl_tool.run("example.com", port=8443, dry_run=True)
    assert "example.com:8443" in result.command


def test_getjs_uses_go_bin_path():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "getJS")):
        result = getjs_tool.run("https://example.com", dry_run=True)
    assert result.command[0] == str(GO_BIN / "getJS")


def test_linkfinder_uses_venv_python_and_script():
    with patch("reconai.tools.base.shutil.which", return_value=LINKFINDER_PYTHON):
        result = linkfinder_tool.run("https://example.com", dry_run=True)
    assert result.command[0] == LINKFINDER_PYTHON
    assert result.command[1].endswith("linkfinder.py")


def test_subjack_dry_run_uses_go_bin_path_and_wordlist_flag():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "subjack")):
        result = subjack_tool.run(["a.example.com", "b.example.com"], dry_run=True)
    assert result.command[0] == str(GO_BIN / "subjack")
    assert "-w" in result.command
    assert "-ssl" in result.command


def test_subjack_writes_subdomains_to_temp_file_for_real_run(tmp_path):
    fake_bin = tmp_path / "subjack"
    fake_bin.write_text("#!/bin/sh\ncat \"$2\"\n")
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.subjack_tool._SUBJACK_BIN", str(fake_bin)):
        result = subjack_tool.run(["a.example.com", "b.example.com"], dry_run=False)
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout


def test_subjack_strips_ansi_color_codes_from_output(tmp_path):
    # subjack prints ANSI color codes unconditionally (no isatty check), so raw
    # escape sequences would otherwise show up as garbled text in the report/dashboard.
    fake_bin = tmp_path / "subjack"
    fake_bin.write_text('#!/bin/sh\nprintf "[\\033[31;1mNot Vulnerable\\033[0m] www.example.com\\n"\n')
    fake_bin.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_bin)), \
         patch("reconai.tools.subjack_tool._SUBJACK_BIN", str(fake_bin)):
        result = subjack_tool.run(["www.example.com"], dry_run=False)
    assert result.stdout == "[Not Vulnerable] www.example.com\n"
    assert "\x1b" not in result.stdout


def test_waybackurls_dry_run_uses_go_bin_path():
    with patch("reconai.tools.base.shutil.which", return_value=str(GO_BIN / "waybackurls")):
        result = waybackurls_tool.run("example.com", dry_run=True)
    assert result.command == [str(GO_BIN / "waybackurls"), "example.com"]


def test_parse_param_urls_filters_non_parameterized():
    stdout = "https://example.com/about\nhttps://example.com/product?id=1\n"
    assert waybackurls_tool.parse_param_urls(stdout) == ["https://example.com/product?id=1"]


def test_parse_param_urls_dedupes_same_path_and_param_names():
    stdout = (
        "https://example.com/product?id=1\n"
        "https://example.com/product?id=2\n"
        "https://example.com/product?id=3&extra=x\n"
    )
    urls = waybackurls_tool.parse_param_urls(stdout)
    # id=2 and id=3 are the same injectable shape as id=1 (same path, same
    # param names) and should be collapsed; id=3&extra=x has a different
    # param-name set and is kept.
    assert urls == ["https://example.com/product?id=1", "https://example.com/product?id=3&extra=x"]


def test_parse_param_urls_respects_limit():
    stdout = "\n".join(f"https://example.com/p{i}?id={i}" for i in range(20))
    assert len(waybackurls_tool.parse_param_urls(stdout, limit=5)) == 5


def test_sqlmap_dry_run_is_locked_to_safe_detection_flags():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/sqlmap"):
        result = sqlmap_tool.run(["https://example.com/?id=1"], dry_run=True)
    assert "--risk=1" in result.command
    assert "--level=1" in result.command
    assert "--batch" in result.command
    for dangerous_flag in ("--dump", "--dump-all", "--os-shell", "--sql-shell", "--os-pwn"):
        assert dangerous_flag not in result.command


def test_sqlmap_writes_urls_to_temp_file_for_real_run(tmp_path, monkeypatch):
    # sqlmap_tool builds cmd[0] as the bare string "sqlmap" (expected on PATH via
    # apt/preinstalled, unlike the Go tools resolved by absolute GO_BIN path) --
    # so faking the binary means putting it on PATH, not patching shutil.which.
    fake_bin = tmp_path / "sqlmap"
    fake_bin.write_text("#!/bin/sh\ncat \"$2\"\n")
    fake_bin.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = sqlmap_tool.run(["https://example.com/?id=1", "https://example.com/?q=x"], dry_run=False)
    assert "https://example.com/?id=1" in result.stdout
    assert "https://example.com/?q=x" in result.stdout


def test_sqlmap_requires_at_least_one_url():
    try:
        sqlmap_tool.run([], dry_run=True)
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# dns_axfr_tool
# ---------------------------------------------------------------------------

def test_dns_axfr_dry_run_does_not_call_subprocess():
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/dig"), \
         patch("reconai.tools.base.subprocess.run") as mock_run:
        result = dns_axfr_tool.run("example.com", dry_run=True)
    mock_run.assert_not_called()
    assert "[DRY-RUN]" in result.stdout


def test_dns_axfr_reports_refused_transfer_as_ok(tmp_path, monkeypatch):
    # dig itself is expected on PATH (apt "dnsutils"), so faking it means
    # putting a fake binary on PATH, same as the sqlmap real-run test.
    # Real +noall +answer format (not a bare hostname): name/ttl/class/type/value.
    fake_dig = tmp_path / "dig"
    fake_dig.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = "NS" ]; then echo "example.com.\t3600\tIN\tNS\tns1.example.com."; '
        'else echo "; Transfer failed."; fi\n'
    )
    fake_dig.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = dns_axfr_tool.run("example.com", dry_run=False)
    assert "no zone transfer (refused/failed) -- OK" in result.stdout
    assert "CRITICAL" not in result.stdout


def test_dns_axfr_flags_successful_zone_transfer_as_critical(tmp_path, monkeypatch):
    fake_dig = tmp_path / "dig"
    fake_dig.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = "NS" ]; then echo "example.com.\t3600\tIN\tNS\tns1.example.com."; '
        'else echo "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 2 3 4 5"; fi\n'
    )
    fake_dig.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = dns_axfr_tool.run("example.com", dry_run=False)
    assert "[CRITICAL] ZONE TRANSFER SUCCEEDED" in result.stdout


def test_dns_axfr_ignores_cname_target_when_extracting_nameservers(tmp_path, monkeypatch):
    # Regression: "dig NS www.example.com +short"-style output for a CNAME'd
    # name mixes the CNAME target in with the real NS records, with nothing
    # to tell them apart -- verified for real against www.banasthali.org,
    # where the CNAME target ("banasthali.org.") was then wrongly treated as
    # one of the target's own nameservers and AXFR-tested against. Filtering
    # on the record-type column (only real "NS" records) fixes it.
    fake_dig = tmp_path / "dig"
    fake_dig.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = "NS" ]; then\n'
        '  echo "www.example.com.\t3600\tIN\tCNAME\texample.com."\n'
        '  echo "example.com.\t3600\tIN\tNS\tns1.example.com."\n'
        'else\n'
        '  echo "; Transfer failed."\n'
        'fi\n'
    )
    fake_dig.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    result = dns_axfr_tool.run("www.example.com", dry_run=False)
    assert "dig @ns1.example.com" in result.stdout
    assert "dig @example.com" not in result.stdout


def test_parse_nameservers_filters_by_record_type():
    dig_output = (
        "www.example.com.\t3600\tIN\tCNAME\texample.com.\n"
        "example.com.\t3600\tIN\tNS\tns1.example.com.\n"
        "example.com.\t3600\tIN\tNS\tns2.example.com.\n"
    )
    assert dns_axfr_tool._parse_nameservers(dig_output) == ["ns1.example.com", "ns2.example.com"]


# ---------------------------------------------------------------------------
# crtsh_tool
# ---------------------------------------------------------------------------

def test_crtsh_parse_subdomains_splits_and_strips_blank_lines():
    # dedup/wildcard-stripping happens in run() while building the clean output
    # (see test_crtsh_real_query_parses_json_response) -- parse_subdomains just
    # splits that already-clean text back into a list, same as subfinder's.
    stdout = "www.example.com\n\n  \napi.example.com\n"
    assert crtsh_tool.parse_subdomains(stdout) == ["www.example.com", "api.example.com"]


def test_crtsh_parse_subdomains_handles_no_certificates_sentinel():
    assert crtsh_tool.parse_subdomains("(no certificates found)") == []


def test_crtsh_dry_run_does_not_make_requests():
    result = crtsh_tool.run("example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout


def test_crtsh_real_query_parses_json_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "*.example.com"},
        ])

    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    with patch("reconai.tools.crtsh_tool.httpx.Client", _MockClient):
        result = crtsh_tool.run("example.com", dry_run=False)
    names = crtsh_tool.parse_subdomains(result.stdout)
    assert names == sorted({"www.example.com", "api.example.com", "example.com"})


# ---------------------------------------------------------------------------
# cve_correlate_tool
# ---------------------------------------------------------------------------

def test_parse_whatweb_extracts_product_and_version():
    stdout = "http://example.com [200 OK] HTTPServer[nginx/1.22.1], IP[93.184.216.34], Nginx[1.22.1]"
    pairs = cve_correlate_tool._parse_whatweb(stdout)
    assert ("nginx", "1.22.1") in pairs


def test_parse_nmap_extracts_product_and_version():
    stdout = "22/tcp   open  ssh     OpenSSH 8.9p1\n80/tcp   open  http    nginx 1.22.1\n"
    pairs = cve_correlate_tool._parse_nmap(stdout)
    assert ("OpenSSH", "8.9p1") in pairs
    assert ("nginx", "1.22.1") in pairs


def test_cve_correlate_no_banners_short_circuits_without_network():
    result = cve_correlate_tool.run("no banners here", "no banners here either", dry_run=False)
    assert "No product/version banners detected" in result.stdout


def test_cve_correlate_queries_nvd_for_detected_banner():
    # only one product/version pair -> no inter-request sleep delay in the test
    with patch("reconai.tools.cve_correlate_tool._query_nvd", return_value=["CVE-2022-41741: test description"]):
        result = cve_correlate_tool.run("Nginx[1.22.1]", "", dry_run=False)
    assert "Nginx 1.22.1" in result.stdout
    assert "CVE-2022-41741" in result.stdout


def test_search_version_strips_patch_letter_suffix():
    # Verified for real against the live NVD API: "OpenSSH 5.3p1" (the exact
    # nmap-detected version) returns 0 results, "OpenSSH 5.3" returns 2 --
    # keywordSearch wants a version actually spelled out in a CVE
    # description, which never includes a patch-letter suffix like this.
    assert cve_correlate_tool._search_version("5.3p1") == "5.3"


def test_search_version_strips_distro_packaging_suffix():
    assert cve_correlate_tool._search_version("5.1.73-0ubuntu0.10.04.1") == "5.1.73"


def test_search_version_leaves_clean_version_untouched():
    assert cve_correlate_tool._search_version("1.22.1") == "1.22.1"


def test_query_nvd_searches_stripped_version_not_full_string():
    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": []}

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, params, headers):
            captured["keywordSearch"] = params["keywordSearch"]
            return _FakeResponse()

    with patch("reconai.tools.cve_correlate_tool.httpx_client", return_value=_FakeClient()):
        cve_correlate_tool._query_nvd("OpenSSH", "5.3p1")
    assert captured["keywordSearch"] == "OpenSSH 5.3"


# ---------------------------------------------------------------------------
# github_secrets_tool
# ---------------------------------------------------------------------------

def test_guess_org_name_from_second_level_label():
    assert github_secrets_tool._guess_org_name("mark8.syfe.com") == "syfe"
    assert github_secrets_tool._guess_org_name("example.com") == "example"


def test_guess_org_name_handles_multi_part_public_suffix():
    # Regression: guessed "gov" for "www.csk.gov.in" before this fix -- which
    # would have pointed github_secrets at whatever GitHub org is actually
    # named "gov" (a real authorization-boundary risk, not just noise).
    assert github_secrets_tool._guess_org_name("www.csk.gov.in") == "csk"


# ---------------------------------------------------------------------------
# base.registrable_domain
# ---------------------------------------------------------------------------

def test_registrable_domain_strips_leading_subdomain_labels():
    # Regression: subfinder/crt.sh queried with the literal scanned hostname
    # "www.banasthali.org" both returned zero subdomains against a live
    # target -- there's no such thing as a sub-subdomain of "www". The same
    # queries against the apex "banasthali.org" turned up 11 real ones.
    from reconai.tools.base import registrable_domain
    assert registrable_domain("www.banasthali.org") == "banasthali.org"
    assert registrable_domain("a.b.www.example.com") == "example.com"


def test_registrable_domain_leaves_apex_domain_unchanged():
    from reconai.tools.base import registrable_domain
    assert registrable_domain("example.com") == "example.com"


def test_registrable_domain_handles_multi_part_public_suffix():
    from reconai.tools.base import registrable_domain
    assert registrable_domain("www.csk.gov.in") == "csk.gov.in"


# ---------------------------------------------------------------------------
# theharvester_tool
# ---------------------------------------------------------------------------

def test_theharvester_uses_only_keyless_working_sources():
    # Regression: "duckduckgo" and "threatcrowd" were previously in the
    # source list but verified for real to never contribute anything --
    # duckduckgo only hits DuckDuckGo's Instant-Answer widget API (not
    # organic search), and threatcrowd's API is defunct. "otx" is kept even
    # though it now needs a free API key to return data (fails gracefully
    # without one), since it's a free upgrade path once a key is added.
    with patch("reconai.tools.theharvester_tool.run_command") as mock_run:
        mock_run.return_value = "stub"
        theharvester_tool.run("example.com")
    cmd = mock_run.call_args.args[1]
    sources = cmd[cmd.index("-b") + 1].split(",")
    assert "duckduckgo" not in sources
    assert "threatcrowd" not in sources
    assert "crtsh" in sources
    assert mock_run.call_args.kwargs["timeout"] >= 180


def test_github_secrets_dry_run_does_not_call_apis(tmp_path):
    fake_trufflehog = tmp_path / "trufflehog"
    fake_trufflehog.write_text("#!/bin/sh\n")
    fake_trufflehog.chmod(0o755)
    with patch("reconai.tools.base.shutil.which", return_value=str(fake_trufflehog)), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", str(fake_trufflehog)):
        result = github_secrets_tool.run("example.com", dry_run=True)
    assert "[DRY-RUN]" in result.stdout
    assert "'example'" in result.stdout


def test_github_secrets_skips_short_org_guess_without_any_api_call():
    # Regression: "csk" (guessed for www.csk.gov.in) turned out to be a real,
    # unrelated GitHub *user* account -- cloning and scanning it would have
    # been a genuine authorization-boundary violation, not just noise. Short
    # guesses are skipped before any lookup/clone happens.
    fake_trufflehog = "/bin/true"
    with patch("reconai.tools.base.shutil.which", side_effect=lambda b: fake_trufflehog if b == fake_trufflehog else "/usr/bin/git"), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", fake_trufflehog), \
         patch("reconai.tools.github_secrets_tool._find_org_repos") as mock_find:
        result = github_secrets_tool.run("www.csk.gov.in", dry_run=False)
    assert result.available is False
    assert "too short" in result.skipped_reason
    mock_find.assert_not_called()


def test_github_secrets_reports_no_org_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    fake_trufflehog = "/bin/true"  # just needs to exist and be executable
    with patch("reconai.tools.base.shutil.which", side_effect=lambda b: fake_trufflehog if b == fake_trufflehog else "/usr/bin/git"), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", fake_trufflehog), \
         patch("reconai.tools.github_secrets_tool.httpx.Client", _MockClient):
        result = github_secrets_tool.run("nonexistent-org-xyz.com", dry_run=False)
    assert "No public GitHub org found" in result.stdout


def test_github_secrets_falls_back_to_user_account_when_no_org_exists():
    # Regression: many companies (especially smaller ones) publish under a
    # personal-style GitHub user account rather than a registered
    # Organization -- /orgs/<name> 404s but /users/<name> has real repos.
    # Confirmed against a real target during Kali verification (github.com
    # api /orgs/syfe/repos -> 404, /users/syfe/repos -> 200).
    def handler(request: httpx.Request) -> httpx.Response:
        if "/orgs/" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, json=[{"clone_url": "https://github.com/example/personal-repo.git"}])

    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    fake_trufflehog = "/bin/true"
    with patch("reconai.tools.base.shutil.which", side_effect=lambda b: fake_trufflehog if b == fake_trufflehog else "/usr/bin/git"), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", fake_trufflehog), \
         patch("reconai.tools.github_secrets_tool.httpx.Client", _MockClient):
        clone_urls = github_secrets_tool._find_org_repos("example")
    assert clone_urls == ["https://github.com/example/personal-repo.git"]


def test_github_secrets_reports_clean_repo_with_no_secrets(tmp_path, monkeypatch):
    fake_git = tmp_path / "git"
    fake_git.write_text('#!/bin/sh\nmkdir -p "$6"\n')
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    fake_trufflehog = tmp_path / "trufflehog"
    fake_trufflehog.write_text('#!/bin/sh\n')
    fake_trufflehog.chmod(0o755)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"clone_url": "https://github.com/exampleorg/clean-repo.git"}])

    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    with patch("reconai.tools.base.shutil.which",
               side_effect=lambda b: str(fake_trufflehog) if b == str(fake_trufflehog) else str(tmp_path / "git")), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", str(fake_trufflehog)), \
         patch("reconai.tools.github_secrets_tool.httpx.Client", _MockClient):
        result = github_secrets_tool.run("example.com", dry_run=False)

    assert "clean-repo" in result.stdout
    assert "no verified secrets found" in result.stdout


def test_github_secrets_reports_verified_secret_finding(tmp_path, monkeypatch):
    # _MAX_REPOS is 1 (each clone+scan is real memory/CPU work -- verified in
    # practice to OOM a 512MB container scanning more), so only the single
    # most-recently-pushed repo the mocked API returns gets cloned and scanned.
    fake_git = tmp_path / "git"
    fake_git.write_text('#!/bin/sh\nmkdir -p "$6"\n')
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    fake_trufflehog = tmp_path / "trufflehog"
    fake_trufflehog.write_text('#!/bin/sh\necho \'{"DetectorName":"AWS","Verified":true}\'\n')
    fake_trufflehog.chmod(0o755)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"clone_url": "https://github.com/exampleorg/secret-repo.git"}])

    class _MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    with patch("reconai.tools.base.shutil.which",
               side_effect=lambda b: str(fake_trufflehog) if b == str(fake_trufflehog) else str(tmp_path / "git")), \
         patch("reconai.tools.github_secrets_tool._TRUFFLEHOG_BIN", str(fake_trufflehog)), \
         patch("reconai.tools.github_secrets_tool.httpx.Client", _MockClient):
        result = github_secrets_tool.run("example.com", dry_run=False)

    assert "secret-repo" in result.stdout
    assert '"Verified":true' in result.stdout


# ---------------------------------------------------------------------------
# google_dorks_tool
# ---------------------------------------------------------------------------

def test_build_dorks_scopes_every_query_to_the_given_domain():
    dorks = google_dorks_tool.build_dorks("example.com")
    assert len(dorks) > 5
    for label, query in dorks:
        assert label  # non-empty
        assert "example.com" in query


def test_build_dorks_includes_a_google_wide_subdomain_crosscheck():
    dorks = google_dorks_tool.build_dorks("example.com")
    queries = [q for _, q in dorks]
    assert any(q.startswith("site:*.example.com") for q in queries)


def test_run_produces_clickable_search_urls_matching_each_query():
    result = google_dorks_tool.run("example.com")
    assert result.available is True
    assert result.returncode == 0
    for label, query in google_dorks_tool.build_dorks("example.com"):
        assert query in result.stdout
        assert google_dorks_tool._search_url(query) in result.stdout


def test_run_never_makes_a_network_call_or_needs_a_binary():
    # Unlike every other tool, this one has nothing to mark unavailable --
    # it's pure local text generation, so it must succeed even with no
    # binaries on PATH and no proxy configured.
    with patch("reconai.tools.base.shutil.which", return_value=None):
        result = google_dorks_tool.run("example.com", proxy="socks5://127.0.0.1:9050")
    assert result.available is True


def test_dry_run_does_not_generate_the_full_dork_list():
    result = google_dorks_tool.run("example.com", dry_run=True)
    assert "DRY-RUN" in result.stdout
    assert "site:example.com" not in result.stdout


def test_mock_mode_returns_canned_output():
    result = google_dorks_tool.run("example.com", mock=True)
    assert result.mocked is True
    assert "example.com" in result.stdout
