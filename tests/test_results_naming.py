import time
from pathlib import Path

from reconai import results
from reconai.tools.base import ToolResult


def test_sanitize_target_strips_special_chars():
    assert results.sanitize_target("https://example.com:8080/path") == "https___example.com_8080_path"


def test_sanitize_target_neutralizes_path_traversal():
    # "." and ".." both survive the char-allowlist unchanged (both are
    # allowed chars) and, on their own, are complete special path
    # components -- Path("results") / ".." resolves to results/'s parent,
    # escaping the intended sandbox entirely.
    assert results.sanitize_target("..") == "_"
    assert results.sanitize_target(".") == "_"
    assert results.sanitize_target("") == "_"


def test_make_run_dir_with_dotdot_target_stays_inside_base(tmp_path):
    run_dir = results.make_run_dir("..", base=tmp_path)
    assert tmp_path in run_dir.parents


def test_make_run_dir_creates_nested_path(tmp_path):
    run_dir = results.make_run_dir("example.com", base=tmp_path)
    assert run_dir.exists()
    assert run_dir.parent.name == "example.com"
    assert run_dir.parent.parent == tmp_path


def test_make_run_dir_no_collision_across_runs(tmp_path):
    first = results.make_run_dir("example.com", base=tmp_path)
    time.sleep(1.1)  # timestamp granularity is 1s
    second = results.make_run_dir("example.com", base=tmp_path)
    assert first != second


def test_write_tool_output_available(tmp_path):
    result = ToolResult(
        tool="whois", command=["whois", "example.com"], available=True,
        returncode=0, stdout="Domain: example.com", stderr="", duration_s=0.1,
    )
    out = results.write_tool_output(tmp_path, "whois", result)
    content = out.read_text()
    assert "Domain: example.com" in content
    assert "$ whois example.com" in content


def test_write_tool_output_skipped(tmp_path):
    result = ToolResult(
        tool="nmap", command=["nmap", "-sV", "example.com"], available=False,
        returncode=None, stdout="", stderr="", duration_s=0.0,
        skipped_reason="'nmap' not found on PATH. Install with: sudo apt install nmap",
    )
    out = results.write_tool_output(tmp_path, "nmap", result)
    content = out.read_text()
    assert "[SKIPPED]" in content
    assert "sudo apt install nmap" in content


def test_write_ai_summary(tmp_path):
    path = results.write_ai_summary(tmp_path, "Narrative summary text.",
                                     ["httpx: skipped -- no subdomains discovered."])
    assert path.exists()
    import json
    data = json.loads(path.read_text())
    assert data == {
        "ai_summary": "Narrative summary text.",
        "skip_note": "httpx: skipped -- no subdomains discovered.",
    }


def test_write_ai_summary_with_no_skip_notes(tmp_path):
    path = results.write_ai_summary(tmp_path, "Narrative summary text.", [])
    import json
    data = json.loads(path.read_text())
    assert data["skip_note"] is None


def test_write_manifest(tmp_path):
    result = ToolResult(
        tool="whois", command=["whois", "example.com"], available=True,
        returncode=0, stdout="ok", stderr="", duration_s=0.1,
    )
    manifest_path = results.write_manifest(tmp_path, "example.com", [result], llm_backend="ollama")
    assert manifest_path.exists()
    assert "example.com" in manifest_path.read_text()
    assert "ollama" in manifest_path.read_text()
