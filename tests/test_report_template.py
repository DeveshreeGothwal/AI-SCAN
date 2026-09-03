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


def test_build_includes_skip_notes():
    backend = _stub_backend()
    md = markdown_report.build(
        "example.com", _sample_results(), backend,
        skip_notes=["No web port found.", "sqlmap: skipped -- no parameterized URLs discovered."],
    )
    assert "No web port found." in md
    assert "sqlmap: skipped -- no parameterized URLs discovered." in md


def test_extract_ai_summary_returns_just_that_section():
    backend = _stub_backend("Interesting summary text here.")
    md = markdown_report.build("example.com", _sample_results(), backend,
                                skip_notes=["nuclei: skipped -- no open web port detected by nmap."])
    extracted = markdown_report.extract_ai_summary(md)
    assert extracted == "Interesting summary text here."
    assert "Raw Findings" not in extracted
    assert "### whois" not in extracted


def test_extract_ai_summary_handles_missing_section():
    assert markdown_report.extract_ai_summary("no markers here at all") == ""


def test_build_includes_impact_analysis_when_a_detector_fires():
    backend = _stub_backend()
    results = _sample_results() + [
        ToolResult(tool="sqlmap", command=["sqlmap", "-u", "https://example.com/?id=1"],
                   available=True, returncode=0,
                   stdout="Parameter: id (GET)\nthe back-end DBMS is MySQL",
                   stderr="", duration_s=1.0),
    ]
    md = markdown_report.build("example.com", results, backend)
    assert "## Potential Impact Analysis" in md
    assert "Confirmed SQL injection" in md
    assert "[CRITICAL]" in md


def test_build_omits_impact_analysis_section_when_nothing_fires():
    backend = _stub_backend()
    md = markdown_report.build("example.com", _sample_results(), backend)
    assert "## Potential Impact Analysis" not in md


def test_extract_ai_summary_stops_before_impact_analysis_section():
    # Regression: the impact-analysis section is deterministic/rule-based, not
    # LLM output -- it must never get swept into the "ai_summary" extraction
    # the dashboard labels as AI-generated.
    backend = _stub_backend("Interesting summary text here.")
    results = _sample_results() + [
        ToolResult(tool="sqlmap", command=["sqlmap"], available=True, returncode=0,
                   stdout="the back-end DBMS is MySQL", stderr="", duration_s=1.0),
    ]
    md = markdown_report.build("example.com", results, backend)
    extracted = markdown_report.extract_ai_summary(md)
    assert extracted == "Interesting summary text here."
    assert "Potential Impact Analysis" not in extracted
    assert "Confirmed SQL injection" not in extracted


def test_extract_first_skip_note_returns_only_the_first():
    backend = _stub_backend()
    md = markdown_report.build(
        "example.com", _sample_results(), backend,
        skip_notes=["httpx: skipped -- no subdomains discovered.",
                    "subjack: skipped -- no subdomains discovered."],
    )
    assert markdown_report.extract_first_skip_note(md) == "httpx: skipped -- no subdomains discovered."


def test_extract_first_skip_note_returns_none_when_no_skips():
    backend = _stub_backend()
    md = markdown_report.build("example.com", _sample_results(), backend, skip_notes=[])
    assert markdown_report.extract_first_skip_note(md) is None


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


def test_pdf_render_does_not_crash_on_non_latin1_unicode(tmp_path):
    # Verified for real: FPDF's core Helvetica font raises
    # FPDFUnicodeEncodingException on a plain curly quote, which is extremely
    # common in scraped page content -- a real target's raw tool output would
    # crash --pdf entirely without this.
    out_path = tmp_path / "summary.pdf"
    body = "A curly quote: “hello”, an em dash —, and an emoji \U0001F600."
    pdf_report.render(body, out_path, "example.com")
    assert out_path.exists()
    assert out_path.stat().st_size > 0


def test_pdf_render_caps_very_large_input(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_report, "_MAX_CHARS", 100)
    out_path = tmp_path / "summary.pdf"
    pdf_report.render("A" * 10000, out_path, "example.com")
    assert out_path.exists()
