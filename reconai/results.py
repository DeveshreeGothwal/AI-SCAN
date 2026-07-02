from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .tools.base import ToolResult

_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_target(target: str) -> str:
    return _SAFE_CHARS_RE.sub("_", target)


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
