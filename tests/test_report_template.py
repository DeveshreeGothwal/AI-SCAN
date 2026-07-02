from unittest.mock import MagicMock

from reconai.report import markdown_report, pdf_report
from reconai.tools.base import ToolResult


def _stub_backend(summary_text: str = "AI-generated narrative summary of findings."):
    backend = MagicMock()
    backend.name = "ollama"
    backend.summarize.return_value = summary_text
    return backend


def _sample_results():
    return [
        ToolResult(tool="whois", command=["whois", "example.com"], available=True,
                   returncode=0, stdout="Domain: example.com", stderr="", duration_s=0.1),
        ToolResult(tool="nmap", command=["nmap", "-sV", "example.com"], available=False,
                   returncode=None, stdout="", stderr="", duration_s=0.0,
                   skipped_reason="'nmap' not found on PATH. Install with: sudo apt install nmap"),
    ]


def test_build_includes_ai_summary_and_raw_findings():
    backend = _stub_backend()
    md = markdown_report.build("example.com", _sample_results(), backend)
    assert "AI-generated narrative summary of findings." in md
    assert "## AI Summary" in md
    assert "## Raw Findings" in md
    assert "### whois" in md
    assert "Domain: example.com" in md
    assert "**Skipped:**" in md


def test_build_includes_stderr_when_present():
    backend = _stub_backend()
    results = [
        ToolResult(tool="gobuster", command=["gobuster", "dir", "-u", "https://example.com"],
                   available=True, returncode=1, stdout="", stderr="wildcard detected, aborting",
                   duration_s=0.1),
    ]
    md = markdown_report.build("example.com", results, backend)
    assert "--- STDERR ---" in md
    assert "wildcard detected, aborting" in md

    # the AI prompt sent to the backend must also carry the stderr, otherwise
    # a tool that aborts with no stdout looks indistinguishable from "no findings"
    prompt = backend.summarize.call_args[0][0]
    assert "wildcard detected, aborting" in prompt


def test_build_includes_skip_note():
    backend = _stub_backend()
    md = markdown_report.build("example.com", _sample_results(), backend, skip_note="No web port found.")
    assert "No web port found." in md


def test_condense_truncates_long_output():
    long_text = "A" * 20000
    condensed = markdown_report._condense(long_text, max_chars=100)
    assert len(condensed) < len(long_text)
    assert "omitted" in condensed


def test_condense_leaves_short_output_untouched():
    text = "short output"
    assert markdown_report._condense(text) == text


def test_summarize_falls_back_to_per_stage_when_prompt_too_large(monkeypatch):
    backend = _stub_backend()
    monkeypatch.setattr(markdown_report, "_COMBINED_PROMPT_CHAR_CEILING", 10)
    markdown_report._summarize_with_fallback(backend, "example.com", _sample_results())
    # one call per stage (2 results split into 2 halves) plus one merge call
    assert backend.summarize.call_count == 3


def test_pdf_render_produces_nonempty_file(tmp_path):
    out_path = tmp_path / "summary.pdf"
    pdf_report.render("Some report body text.", out_path, "example.com")
    assert out_path.exists()
    assert out_path.stat().st_size > 0
