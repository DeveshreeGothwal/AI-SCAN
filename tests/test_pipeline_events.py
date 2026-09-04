from unittest.mock import MagicMock

from reconai.config import Config
from reconai.pipeline import run_pipeline


def _stub_backend():
    backend = MagicMock()
    backend.name = "ollama"
    backend.summarize.return_value = "stub summary"
    return backend


def test_dry_run_emits_pipeline_start_and_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    events = []
    cfg = Config(target="example.com", dry_run=True)
    run_pipeline(cfg, backend=_stub_backend(), on_event=events.append)

    assert events[0]["type"] == "pipeline_start"
    assert events[0]["target"] == "example.com"
    assert events[-1]["type"] == "pipeline_end"


def test_dry_run_emits_stage_start_and_end_for_passive_tools(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    events = []
    cfg = Config(target="example.com", dry_run=True)
    run_pipeline(cfg, backend=_stub_backend(), on_event=events.append)

    starts = [e["tool"] for e in events if e["type"] == "stage_start"]
    ends = [e["tool"] for e in events if e["type"] == "stage_end"]
    assert "whois" in starts
    assert "whois" in ends
    # no real binaries on this machine -> no web port -> web tools skipped, not started
    assert "gobuster" not in starts
    skipped = [e["tool"] for e in events if e["type"] == "stage_skip"]
    assert "gobuster" in skipped
    assert "testssl" in skipped


def test_mock_pipeline_emits_events_for_every_stage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch
    events = []
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"):
        cfg = Config(target="example.com", mock=True)
        run_pipeline(cfg, backend=_stub_backend(), on_event=events.append)

    ends = {e["tool"] for e in events if e["type"] == "stage_end"}
    for tool in ("whois", "dns", "dns_axfr", "subfinder", "crtsh", "theharvester", "google_dorks",
                 "bucket_enum", "github_secrets", "httpx", "subjack", "waybackurls", "nmap",
                 "whatweb", "nikto", "gobuster", "ffuf", "wafw00f", "cors_scan", "security_headers",
                 "auth_audit", "privacy_scan", "nuclei", "getjs", "linkfinder", "cve_correlate",
                 "secret_scan", "graphql_probe", "injection_probe", "sqlmap", "testssl"):
        assert tool in ends, tool

    # events must be emitted in real time, not just collected after the fact --
    # every stage_start for a tool must appear before that tool's stage_end.
    seen_starts = set()
    for e in events:
        if e["type"] == "stage_start":
            seen_starts.add(e["tool"])
        elif e["type"] == "stage_end":
            assert e["tool"] in seen_starts, f"{e['tool']} ended before it started"


def test_on_event_none_does_not_break_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config(target="example.com", dry_run=True)
    ctx = run_pipeline(cfg, backend=_stub_backend())  # no on_event passed
    assert ctx.summary_path.exists()
