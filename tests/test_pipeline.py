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
    assert ctx.skip_note is not None


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
        "nuclei.txt", "getjs.txt", "linkfinder.txt", "testssl.txt", "gowitness.txt",
        "httpx.txt", "subjack.txt",
    ):
        assert (ctx.run_dir / tool_file).exists(), tool_file
    assert ctx.skip_note is None

    manifest = json.loads((ctx.run_dir / "manifest.json").read_text())
    assert manifest["target"] == "example.com"
    assert manifest["llm_backend"] == "ollama"
    # whois, dns, subfinder, theharvester, httpx, subjack, nmap, whatweb, nikto,
    # gobuster, ffuf, wafw00f, nuclei, getjs, linkfinder, testssl, gowitness
    assert len(manifest["tools"]) == 17

    # mock nmap output has both 80/http and 443/https open -- must prefer https,
    # since sites that redirect http->https break gobuster's wildcard detection.
    whatweb_cmd = (ctx.run_dir / "whatweb.txt").read_text()
    assert "https://example.com" in whatweb_cmd

    # testssl only makes sense against the https port -- must run there, not http.
    testssl_cmd = (ctx.run_dir / "testssl.txt").read_text()
    assert "443" in testssl_cmd


def test_httpx_skipped_when_subfinder_finds_no_subdomains(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch

    from reconai.tools.mock_data import MOCK_OUTPUTS
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         patch.dict(MOCK_OUTPUTS, {"subfinder": ""}):
        cfg = Config(target="example.com", mock=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())

    assert not (ctx.run_dir / "httpx.txt").exists()
    assert not (ctx.run_dir / "subjack.txt").exists()


def test_pdf_flag_renders_pdf(tmp_path, monkeypatch):
    from unittest.mock import patch
    monkeypatch.chdir(tmp_path)
    with patch("reconai.tools.base.shutil.which", return_value=None):
        cfg = Config(target="example.com", dry_run=True, render_pdf=True)
        ctx = run_pipeline(cfg, backend=_stub_backend())
    assert ctx.pdf_path.exists()
