from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .report.impact_analysis import ImpactFinding
from .tools.base import ToolResult

_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_target(target: str) -> str:
    sanitized = _SAFE_CHARS_RE.sub("_", target)
    # The regex above strips slashes, so the result is always a single path
    # component -- except "." and ".." survive unchanged (both are in the
    # allowed charset), and either one *is* a complete, special path
    # component on its own ("." = same dir, ".." = parent dir). A target of
    # exactly ".." would otherwise make make_run_dir() write outside
    # results/ entirely (Path("results") / ".." resolves to its parent).
    if sanitized in ("", ".", ".."):
        return "_"
    return sanitized


def make_run_dir(target: str, base: Path = Path("results")) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = base / sanitize_target(target) / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def write_tool_output(run_dir: Path, tool_name: str, result: ToolResult) -> Path:
    out_path = run_dir / f"{tool_name}.txt"
    lines = [f"$ {' '.join(result.command)}", ""]
    if not result.available:
        lines.append(f"[SKIPPED] {result.skipped_reason}")
    else:
        lines.append(result.stdout)
        if result.stderr:
            lines += ["", "--- STDERR ---", result.stderr]
    out_path.write_text("\n".join(lines))
    return out_path


def write_ai_summary(run_dir: Path, ai_summary: str, skip_notes: list[str]) -> Path:
    """Small companion file to summary.md so the dashboard's report view can
    fetch just the narrative summary without downloading the entire
    (potentially huge) report. skip_notes stores only the first entry,
    matching the one generic "why is this tool missing" message the
    dashboard has always shown for any tool absent from the manifest --
    not a behavior change, just moving where that string comes from."""
    path = run_dir / "ai_summary.json"
    path.write_text(json.dumps({
        "ai_summary": ai_summary,
        "skip_note": skip_notes[0] if skip_notes else None,
    }, indent=2))
    return path


def write_impact_analysis(run_dir: Path, findings: list[ImpactFinding], score: int, grade: str) -> Path:
    """Small companion file (same pattern as write_ai_summary above) so the
    dashboard's Security Score card can fetch this without downloading/
    re-parsing the full markdown report."""
    path = run_dir / "impact.json"
    path.write_text(json.dumps({
        "findings": [
            {"title": f.title, "severity": f.severity, "evidence": f.evidence,
             "impact": f.impact, "recommendation": f.recommendation}
            for f in findings
        ],
        "score": score,
        "grade": grade,
    }, indent=2))
    return path


def write_manifest(run_dir: Path, target: str, results: list[ToolResult], llm_backend: str, extra: dict | None = None) -> Path:
    manifest = {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "llm_backend": llm_backend,
        "tools": [
            {
                "tool": r.tool,
                "available": r.available,
                "returncode": r.returncode,
                "duration_s": round(r.duration_s, 2),
                "skipped_reason": r.skipped_reason,
                "mocked": r.mocked,
            }
            for r in results
        ],
    }
    if extra:
        manifest.update(extra)
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest_path
