import json
from unittest.mock import MagicMock

from reconai.config import Config
from reconai.pipeline import run_pipeline


def _stub_backend():
    backend = MagicMock()
    backend.name = "ollama"
    backend.summarize.return_value = "stub summary"
    return backend


def test_dry_run_pipeline_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config(target="example.com", dry_run=True)
    ctx = run_pipeline(cfg, backend=_stub_backend())

    assert ctx.summary_path.exists()
    assert (ctx.run_dir / "manifest.json").exists()
    assert (ctx.run_dir / "whois.txt").exists()
    assert (ctx.run_dir / "nmap.txt").exists()
    # no real binaries on this machine -> nmap unavailable -> no web port -> web tools skipped
    assert not (ctx.run_dir / "whatweb.txt").exists()
    assert ctx.skip_notes  # non-empty: whatweb/nikto/etc. all recorded as skipped


def test_mock_pipeline_detects_web_port_and_runs_web_tools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # --mock returns canned output including an open http port, but shutil.which
    # still gates whether the tool is considered "available" -- patch it so mock
    # tool output is actually used.
    from unittest.mock import patch
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"):
        cfg = Config(target="example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())

    for tool_file in (
        "whatweb.txt", "nikto.txt", "gobuster.txt", "ffuf.txt", "wafw00f.txt",
        "nuclei.txt", "getjs.txt", "linkfinder.txt", "testssl.txt",
        "httpx.txt", "subjack.txt", "waybackurls.txt", "injection_probe.txt", "sqlmap.txt",
        "dns_axfr.txt", "crtsh.txt", "bucket_enum.txt", "github_secrets.txt",
        "cve_correlate.txt", "secret_scan.txt", "cors_scan.txt", "security_headers.txt",
        "graphql_probe.txt", "google_dorks.txt", "auth_audit.txt", "privacy_scan.txt",
    ):
        assert (ctx.run_dir / tool_file).exists(), tool_file
    assert ctx.skip_notes == []

    manifest = json.loads((ctx.run_dir / "manifest.json").read_text())
    assert manifest["target"] == "example.com"
    assert manifest["llm_backend"] == "ollama"
    # whois, dns, dns_axfr, subfinder, crtsh, theharvester, google_dorks, bucket_enum,
    # github_secrets, httpx, subjack, waybackurls, nmap, whatweb, nikto, gobuster, ffuf,
    # wafw00f, cors_scan, security_headers, auth_audit, privacy_scan, nuclei, getjs,
    # linkfinder, cve_correlate, secret_scan, graphql_probe, injection_probe, sqlmap,
    # testssl
    assert len(manifest["tools"]) == 31

    impact = json.loads((ctx.run_dir / "impact.json").read_text())
    assert "findings" in impact and "score" in impact and "grade" in impact

    # mock nmap output has both 80/http and 443/https open -- must prefer https,
    # since sites that redirect http->https break gobuster's wildcard detection.
    whatweb_cmd = (ctx.run_dir / "whatweb.txt").read_text()
    assert "https://example.com" in whatweb_cmd

    # testssl only makes sense against the https port -- must run there, not http.
    testssl_cmd = (ctx.run_dir / "testssl.txt").read_text()
    assert "443" in testssl_cmd


def test_crtsh_subdomains_merged_with_subfinder_for_httpx(tmp_path, monkeypatch):
    # httpx/subjack both return canned output regardless of input in mock mode,
    # so verifying the merge means intercepting what subdomains list they're
    # actually called with, not reading their (mocked) output afterward.
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch

    from reconai.tools.base import ToolResult as _TR
    captured = {}

    def fake_httpx_run(subdomains, dry_run=False, mock=False, proxy=None):
        captured["subdomains"] = subdomains
        return _TR(tool="httpx", command=["httpx"], available=True, returncode=0, stdout="", stderr="", duration_s=0.0)

    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         patch("reconai.pipeline.httpx_tool.run", side_effect=fake_httpx_run):
        cfg = Config(target="example.com", mock=True)
        run_pipeline(cfg, backend=_stub_backend())

    # mock subfinder output: www/api/staging/mail.example.com
    # mock crtsh output: www/api/old-vpn.example.com
    assert "old-vpn.example.com" in captured["subdomains"]  # crtsh-only
    assert "staging.example.com" in captured["subdomains"]  # subfinder-only


def test_httpx_skipped_when_subfinder_finds_no_subdomains(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch

    from reconai.tools.mock_data import MOCK_OUTPUTS
    # subdomains now merge subfinder + crtsh -- both need to be empty for the
    # "no subdomains discovered" skip path to trigger.
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         patch.dict(MOCK_OUTPUTS, {"subfinder": "", "crtsh": "(no certificates found)"}):
        cfg = Config(target="example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())

    assert not (ctx.run_dir / "httpx.txt").exists()
    assert not (ctx.run_dir / "subjack.txt").exists()

    # regression: a skip reason must survive into the persisted report, not just
    # the live dashboard's SSE stream -- otherwise a report read later can't
    # tell "forgot to run this tool" from "deliberately skipped it".
    assert any("httpx" in note and "no subdomains" in note for note in ctx.skip_notes)
    assert any("subjack" in note and "no subdomains" in note for note in ctx.skip_notes)
    summary = ctx.summary_path.read_text()
    assert "httpx: skipped -- no subdomains discovered." in summary


def test_apex_domain_tools_receive_registrable_domain_not_literal_target(tmp_path, monkeypatch):
    # Regression: subfinder/crt.sh/theHarvester were being called with the
    # literal scanned hostname (e.g. "www.example.com") -- verified for real
    # against a live target that this returns zero subdomains, since there's
    # no such thing as a sub-subdomain of "www". They need the apex/
    # registrable domain instead; tools that actively touch the exact target
    # (whois here as a representative) must stay scoped to the literal target.
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch

    from reconai.tools.base import ToolResult as _TR
    captured = {}

    def make_fake(name):
        def fake_run(target, dry_run=False, mock=False, proxy=None):
            captured[name] = target
            return _TR(tool=name, command=[name], available=True, returncode=0,
                       stdout="", stderr="", duration_s=0.0)
        return fake_run

    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         patch("reconai.pipeline.subfinder_tool.run", side_effect=make_fake("subfinder")), \
         patch("reconai.pipeline.crtsh_tool.run", side_effect=make_fake("crtsh")), \
         patch("reconai.pipeline.theharvester_tool.run", side_effect=make_fake("theharvester")), \
         patch("reconai.pipeline.google_dorks_tool.run", side_effect=make_fake("google_dorks")), \
         patch("reconai.pipeline.whois_tool.run", side_effect=make_fake("whois")):
        cfg = Config(target="www.example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())

    assert captured["subfinder"] == "example.com"
    assert captured["crtsh"] == "example.com"
    assert captured["theharvester"] == "example.com"
    assert captured["google_dorks"] == "example.com"
    assert captured["whois"] == "www.example.com"

    assert any("registrable domain" in note and "example.com" in note for note in ctx.skip_notes)


def test_no_registrable_domain_note_when_target_is_already_apex(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"):
        cfg = Config(target="example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())
    assert not any("registrable domain" in note for note in ctx.skip_notes)


def test_injection_probe_and_sqlmap_skipped_when_no_param_urls(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch

    from reconai.tools.mock_data import MOCK_OUTPUTS
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         patch.dict(MOCK_OUTPUTS, {"waybackurls": "https://example.com/about\n"}):
        cfg = Config(target="example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())

    assert (ctx.run_dir / "waybackurls.txt").exists()
    assert not (ctx.run_dir / "injection_probe.txt").exists()
    assert not (ctx.run_dir / "sqlmap.txt").exists()

    summary = ctx.summary_path.read_text()
    assert "injection_probe: skipped -- no parameterized URLs discovered." in summary
    assert "sqlmap: skipped -- no parameterized URLs discovered." in summary


def test_pdf_flag_renders_pdf(tmp_path, monkeypatch):
    from unittest.mock import patch
    monkeypatch.chdir(tmp_path)
    with patch("reconai.tools.base.shutil.which", return_value=None):
        cfg = Config(target="example.com", dry_run=True, render_pdf=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())
    assert ctx.pdf_path.exists()


def test_pdf_render_failure_does_not_fail_the_whole_run(tmp_path, monkeypatch):
    # A bonus export (--pdf) failing must not erase an otherwise-successful
    # scan -- summary.md is already written by the time this renders.
    from unittest.mock import patch
    monkeypatch.chdir(tmp_path)
    with patch("reconai.tools.base.shutil.which", return_value=None), \
         patch("reconai.pipeline.pdf_report.render", side_effect=RuntimeError("boom")):
        cfg = Config(target="example.com", dry_run=True, render_pdf=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())
    assert ctx.pdf_path is None
    assert ctx.pdf_error == "boom"
    assert ctx.summary_path.exists()
