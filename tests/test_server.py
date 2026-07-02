import time
from pathlib import Path

from fastapi.testclient import TestClient

from reconai.server.app import _run_dir_for, app
from reconai.server.events import registry


def _wait_for_summary(client: TestClient, run_id: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/runs/{run_id}/summary")
        if resp.status_code == 200:
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
        assert "gowitness" in tool_names

        nmap_output = client.get(f"/runs/{run_id}/tool/nmap")
        assert nmap_output.status_code == 200
        assert "example.com" in nmap_output.text


def test_scan_rejects_unknown_wordlist_size():
    with TestClient(app) as client:
        resp = client.post(
            "/scan",
            json={"target": "example.com", "dry_run": True, "authorized": True, "wordlist_size": "huge"},
        )
    assert resp.status_code == 400
    assert "wordlist_size" in resp.json()["error"]


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


def test_screenshot_404_for_unknown_run():
    with TestClient(app) as client:
        resp = client.get("/runs/does-not-exist/screenshot")
    assert resp.status_code == 404
