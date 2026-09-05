import time
from pathlib import Path

from fastapi.testclient import TestClient

from reconai.server.app import _run_dir_for, app
from reconai.server.events import registry


def _wait_for_summary(client: TestClient, run_id: str, timeout: float = 5.0) -> str:
    # summary.md is written *before* impact analysis, the PDF render, and
    # manifest.json -- waiting only for it (as this used to) races those,
    # since a caller checking /manifest or /pdf right after can catch the
    # worker thread still mid-pipeline. Waiting for the run to be marked
    # done too (only set at pipeline_end, strictly after all of that) closes
    # the gap.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/runs/{run_id}/summary")
        if resp.status_code == 200:
            runs = client.get("/runs").json()
            if any(r["run_id"] == run_id and r["done"] for r in runs):
                return resp.text
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not complete within {timeout}s")


def test_index_serves_dashboard():
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 200
    assert "reconai" in resp.text.lower()


def test_scan_requires_target():
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "", "authorized": True})
    assert resp.status_code == 400


def test_scan_requires_authorization():
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "authorized": False})
    assert resp.status_code == 400
    assert "authoriz" in resp.json()["error"].lower()


def test_scan_runs_end_to_end_and_summary_becomes_available(tmp_path, monkeypatch):
    # results/<target>/<timestamp>/ only has second-granularity, so two scans of
    # the same target in the same test session can collide on a shared results/
    # dir unless each test gets its own cwd.
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]

        summary = _wait_for_summary(client, run_id)
        assert "Recon Summary: example.com" in summary

        events_resp = client.get(f"/events/{run_id}")
        assert events_resp.status_code == 200
        assert events_resp.headers["content-type"].startswith("text/event-stream")
        assert "pipeline_end" in events_resp.text


def test_list_runs_includes_started_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        runs = client.get("/runs").json()
        matching = [r for r in runs if r["run_id"] == run_id]
        assert len(matching) == 1
        assert matching[0]["target"] == "example.com"
        assert matching[0]["done"] is True
        assert "started_at" in matching[0]


def test_run_dir_resolves_from_pipeline_start_before_scan_finishes():
    # regression check: per-tool output must be fetchable while a scan is
    # still running (right after each tool finishes), not just once the whole
    # pipeline completes -- so the live dashboard can let you click an
    # already-done node mid-scan instead of waiting for pipeline_end.
    registry.create("mid-scan-run", "example.com")
    registry.publish("mid-scan-run", {
        "type": "pipeline_start", "target": "example.com",
        "run_dir": "results/example.com/xyz", "stages": [],
    })
    registry.publish("mid-scan-run", {"type": "stage_start", "tool": "whois"})
    # no pipeline_end published -- the scan is still "running"
    assert _run_dir_for("mid-scan-run") == Path("results/example.com/xyz")


def test_manifest_and_tool_output_available_after_mock_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         TestClient(app) as client:
        # dry_run=True alongside mock=True avoids a real network call to Ollama for the
        # AI summary (only dry_run selects DryRunBackend); mock still wins for tool output
        # since run_command checks mock_output before dry_run.
        resp = client.post("/scan", json={"target": "example.com", "mock": True, "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        manifest = client.get(f"/runs/{run_id}/manifest").json()
        assert manifest["target"] == "example.com"
        tool_names = {t["tool"] for t in manifest["tools"]}
        assert "nmap" in tool_names
        assert "testssl" in tool_names

        nmap_output = client.get(f"/runs/{run_id}/tool/nmap")
        assert nmap_output.status_code == 200
        assert "example.com" in nmap_output.text

        # The dashboard fetches this small, pre-extracted payload instead of
        # the whole summary.md, which embeds every tool's full raw output --
        # verified in practice to reach tens of MB for a target with a large
        # waybackurls archive.
        ai_summary = client.get(f"/runs/{run_id}/ai-summary").json()
        assert ai_summary["ai_summary"] == "[DRY-RUN] AI summarization skipped -- no LLM was called."
        assert ai_summary["skip_notes"] == []


def test_ai_summary_falls_back_to_full_report_for_runs_without_companion_file(tmp_path, monkeypatch):
    # Simulates a run persisted before write_ai_summary() existed: only
    # summary.md on disk, no ai_summary.json companion file.
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "mock": True, "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        run_dir = _run_dir_for(run_id)
        (run_dir / "ai_summary.json").unlink()

        ai_summary = client.get(f"/runs/{run_id}/ai-summary").json()
    assert ai_summary["ai_summary"] == "[DRY-RUN] AI summarization skipped -- no LLM was called."


def test_ai_summary_not_ready_before_run_dir_exists():
    with TestClient(app) as client:
        resp = client.get("/runs/nonexistent-run-id/ai-summary")
    assert resp.status_code == 404


def test_scan_rejects_when_another_scan_is_already_running():
    registry.create("already-running", "other.com")  # no pipeline_end -- still "running"
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
    assert resp.status_code == 409
    assert "already running" in resp.json()["error"].lower()


def test_scan_rejects_unknown_wordlist_size():
    with TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={"target": "example.com", "dry_run": True, "authorized": True, "wordlist_size": "huge"},
        )
    assert resp.status_code == 400
    assert "wordlist_size" in resp.json()["error"]


def test_scan_rejects_unrecognized_proxy_scheme():
    with TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={"target": "example.com", "dry_run": True, "authorized": True, "proxy": "ftp://127.0.0.1:21"},
        )
    assert resp.status_code == 400
    assert "proxy" in resp.json()["error"].lower()


def test_scan_accepts_valid_proxy_and_reaches_the_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={"target": "example.com", "dry_run": True, "authorized": True, "proxy": "socks5://127.0.0.1:9050"},
        )
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]
        summary = _wait_for_summary(client, run_id)
    # dry-run's per-tool "[DRY-RUN] would execute" message reflects the
    # proxychains-wrapped command whenever a proxy is configured.
    assert "proxychains4" in summary


def test_scan_accepts_validate_secrets_and_reaches_the_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from unittest.mock import patch
    # secret_scan only runs once a web port is detected, which needs mock=True
    # here since there are no real binaries on this dev machine (same reason
    # test_manifest_and_tool_output_available_after_mock_run pairs mock+dry_run).
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={"target": "example.com", "mock": True, "dry_run": True, "authorized": True,
                  "validate_secrets": True},
        )
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        secret_scan_output = client.get(f"/runs/{run_id}/tool/secret_scan")
    assert secret_scan_output.status_code == 200


def test_scan_wordlist_size_selects_gobuster_wordlist_tier(tmp_path, monkeypatch):
    from unittest.mock import patch

    from reconai.tools.gobuster_tool import WORDLIST_TIERS

    monkeypatch.chdir(tmp_path)
    # mock=True + dry_run=True: mock supplies canned tool output (so a real gobuster
    # binary isn't needed) while dry_run avoids a real network call to Ollama for the
    # AI summary; shutil.which is patched so every tool is considered "available" and
    # web tools (gated on nmap finding an open port) actually run.
    with patch("reconai.tools.base.shutil.which", return_value="/usr/bin/tool"), \
         TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={
                "target": "example.com", "dry_run": True, "mock": True,
                "authorized": True, "wordlist_size": "medium",
            },
        )
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        gobuster_output = client.get(f"/runs/{run_id}/tool/gobuster")
    assert WORDLIST_TIERS["medium"] in gobuster_output.text


def test_tool_output_rejects_unknown_tool_name():
    with TestClient(app) as client:
        resp = client.get("/runs/some-run/tool/passwd")
    assert resp.status_code == 404


def test_manifest_404_for_unknown_run():
    with TestClient(app) as client:
        resp = client.get("/runs/does-not-exist/manifest")
    assert resp.status_code == 404


def test_summary_404_for_unknown_run():
    with TestClient(app) as client:
        resp = client.get("/runs/does-not-exist/summary")
    assert resp.status_code == 404


def test_pdf_downloadable_after_scan(tmp_path, monkeypatch):
    # Every dashboard-triggered scan renders a PDF (unlike the CLI, where
    # --pdf is opt-in) so the report is downloadable straight from the results view.
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        pdf_resp = client.get(f"/runs/{run_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"


def test_pdf_404_for_unknown_run():
    with TestClient(app) as client:
        resp = client.get("/runs/does-not-exist/pdf")
    assert resp.status_code == 404


def test_impact_available_after_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        impact = client.get(f"/runs/{run_id}/impact").json()
    # dry-run never actually executes a tool, so impact_analysis has nothing
    # to detect -- a clean, deterministic "perfect score" result to assert on.
    assert impact["available"] is True
    assert impact["findings"] == []
    assert impact["score"] == 100
    assert impact["grade"] == "A"


def test_impact_not_ready_before_run_dir_exists():
    with TestClient(app) as client:
        resp = client.get("/runs/nonexistent-run-id/impact")
    assert resp.status_code == 404


def test_impact_returns_empty_state_for_runs_without_companion_file(tmp_path, monkeypatch):
    # Simulates a run persisted before write_impact_analysis() existed: no
    # impact.json companion file on disk -- same fallback shape as ai-summary's
    # equivalent regression test above.
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
        run_id = resp.json()["run_id"]
        _wait_for_summary(client, run_id)

        run_dir = _run_dir_for(run_id)
        (run_dir / "impact.json").unlink()

        impact = client.get(f"/runs/{run_id}/impact").json()
    assert impact["available"] is False
    assert impact["findings"] == []
    assert impact["score"] is None


def test_check_link_requires_url():
    with TestClient(app) as client:
        resp = client.post("/check-link", json={"url": ""})
    assert resp.status_code == 400


def test_check_link_returns_findings_from_link_safety_tool():
    from unittest.mock import patch

    from reconai.tools.base import ToolResult

    canned = ToolResult(tool="link_safety", command=["reconai-link-safety"], available=True, returncode=0,
                         stdout="Checked https://example.com\n\nVerdict: LOOKS SAFE\n\nNo risk signals detected.",
                         stderr="", duration_s=0.1)
    with patch("reconai.server.app.link_safety_tool.run", return_value=canned), TestClient(app) as client:
        resp = client.post("/check-link", json={"url": "https://example.com"})
    assert resp.status_code == 200
    assert "LOOKS SAFE" in resp.json()["output"]


def test_check_link_adds_https_scheme_when_missing():
    from unittest.mock import patch

    from reconai.tools.base import ToolResult

    canned = ToolResult(tool="link_safety", command=["reconai-link-safety"], available=True, returncode=0,
                         stdout="ok", stderr="", duration_s=0.1)
    with patch("reconai.server.app.link_safety_tool.run", return_value=canned) as mock_run, \
         TestClient(app) as client:
        resp = client.post("/check-link", json={"url": "example.com/page"})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://example.com/page"
    mock_run.assert_called_once()
    assert mock_run.call_args[0][0] == "https://example.com/page"


def test_check_link_surfaces_tool_unavailable_as_502():
    from unittest.mock import patch

    from reconai.tools.base import ToolResult

    canned = ToolResult(tool="link_safety", command=["reconai-link-safety"], available=False, returncode=None,
                         stdout="", stderr="", duration_s=0.0, skipped_reason="proxy requested but unavailable")
    with patch("reconai.server.app.link_safety_tool.run", return_value=canned), TestClient(app) as client:
        resp = client.post("/check-link", json={"url": "https://example.com"})
    assert resp.status_code == 502


def test_basic_auth_is_a_noop_when_env_vars_unset(monkeypatch):
    monkeypatch.delenv("DASHBOARD_BASIC_AUTH_USER", raising=False)
    monkeypatch.delenv("DASHBOARD_BASIC_AUTH_PASS", raising=False)
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 200


def test_basic_auth_rejects_missing_credentials_when_configured(monkeypatch):
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_USER", "judge")
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_PASS", "s3cret")
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Basic realm="reconai"'


def test_basic_auth_rejects_wrong_credentials_when_configured(monkeypatch):
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_USER", "judge")
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_PASS", "s3cret")
    with TestClient(app) as client:
        resp = client.get("/", auth=("judge", "wrong-password"))
    assert resp.status_code == 401


def test_basic_auth_accepts_correct_credentials_when_configured(monkeypatch):
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_USER", "judge")
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_PASS", "s3cret")
    with TestClient(app) as client:
        resp = client.get("/", auth=("judge", "s3cret"))
    assert resp.status_code == 200


def test_healthz_bypasses_basic_auth_when_configured(monkeypatch):
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_USER", "judge")
    monkeypatch.setenv("DASHBOARD_BASIC_AUTH_PASS", "s3cret")
    with TestClient(app) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200


def test_scan_allowlist_is_a_noop_when_env_var_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOWED_SCAN_TARGETS", raising=False)
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
    assert resp.status_code == 200


def test_scan_allowlist_rejects_target_not_in_list(monkeypatch):
    monkeypatch.setenv("ALLOWED_SCAN_TARGETS", "scanme.nmap.org")
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
    assert resp.status_code == 400
    assert "scanme.nmap.org" in resp.json()["error"]


def test_scan_allowlist_accepts_target_in_list(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOWED_SCAN_TARGETS", "scanme.nmap.org, example.com")
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/scan", json={"target": "example.com", "dry_run": True, "authorized": True})
    assert resp.status_code == 200
