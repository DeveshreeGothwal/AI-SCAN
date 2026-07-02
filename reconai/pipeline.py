from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import results
from .config import Config
from .llm import factory
from .llm.base import LLMBackend
from .llm.null_backend import DryRunBackend
from .report import markdown_report, pdf_report
from .tools import (
    dns_tool,
    ffuf_tool,
    getjs_tool,
    gobuster_tool,
    gowitness_tool,
    httpx_tool,
    linkfinder_tool,
    nikto_tool,
    nmap_tool,
    nuclei_tool,
    subfinder_tool,
    subjack_tool,
    testssl_tool,
    theharvester_tool,
    wafw00f_tool,
    whatweb_tool,
    whois_tool,
)
from .tools.base import ToolResult

PASSIVE_TOOLS = (whois_tool, dns_tool, subfinder_tool, theharvester_tool)
# gobuster and ffuf both need a wordlist, handled as a special case below.
WEB_TOOLS = (whatweb_tool, nikto_tool, gobuster_tool, ffuf_tool, wafw00f_tool, nuclei_tool, getjs_tool, linkfinder_tool)
_WORDLIST_TOOLS = (gobuster_tool, ffuf_tool)

# Full set of stages a run can go through, in order. Some are conditionally
# skipped (httpx needs subdomains, the web-only tools need an open web port).
# A progress UI can use this to render every stage up front as "pending".
STAGE_ORDER = (
    "whois", "dns", "subfinder", "theharvester",
    "httpx", "subjack", "nmap",
    "whatweb", "nikto", "gobuster", "ffuf", "wafw00f", "nuclei", "getjs", "linkfinder",
    "testssl", "gowitness",
    "ai_summary",
)

EventCallback = Callable[[dict], None]


def _emit(on_event: EventCallback | None, event: dict) -> None:
    if on_event is not None:
        on_event(event)


def _stage_end_event(result: ToolResult) -> dict:
    return {
        "type": "stage_end",
        "tool": result.tool,
        "available": result.available,
        "returncode": result.returncode,
        "duration_s": round(result.duration_s, 2),
        "skipped_reason": result.skipped_reason,
    }


@dataclass
class RunContext:
    target: str
    run_dir: Path
    results: list[ToolResult] = field(default_factory=list)
    skip_note: str | None = None
    summary_path: Path | None = None
    pdf_path: Path | None = None


def _base_url(target: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{target}"
    return f"{scheme}://{target}:{port}"


def run_pipeline(cfg: Config, backend: LLMBackend | None = None, on_event: EventCallback | None = None) -> RunContext:
    run_dir = results.make_run_dir(cfg.target)
    ctx = RunContext(target=cfg.target, run_dir=run_dir)
    _emit(on_event, {"type": "pipeline_start", "target": cfg.target, "run_dir": str(run_dir), "stages": list(STAGE_ORDER)})

    for tool_module in PASSIVE_TOOLS:
        _emit(on_event, {"type": "stage_start", "tool": tool_module.NAME})
        result = tool_module.run(cfg.target, dry_run=cfg.dry_run, mock=cfg.mock)
        results.write_tool_output(run_dir, tool_module.NAME, result)
        ctx.results.append(result)
        _emit(on_event, _stage_end_event(result))

    subfinder_result = next(r for r in ctx.results if r.tool == subfinder_tool.NAME)
    subdomains = subfinder_tool.parse_subdomains(subfinder_result.stdout) if subfinder_result.available else []
    if subdomains:
        _emit(on_event, {"type": "stage_start", "tool": httpx_tool.NAME})
        httpx_result = httpx_tool.run(subdomains, dry_run=cfg.dry_run, mock=cfg.mock)
        results.write_tool_output(run_dir, httpx_tool.NAME, httpx_result)
        ctx.results.append(httpx_result)
        _emit(on_event, _stage_end_event(httpx_result))

        _emit(on_event, {"type": "stage_start", "tool": subjack_tool.NAME})
        subjack_result = subjack_tool.run(subdomains, dry_run=cfg.dry_run, mock=cfg.mock)
        results.write_tool_output(run_dir, subjack_tool.NAME, subjack_result)
        ctx.results.append(subjack_result)
        _emit(on_event, _stage_end_event(subjack_result))
    else:
        _emit(on_event, {"type": "stage_skip", "tool": httpx_tool.NAME, "reason": "no subdomains discovered"})
        _emit(on_event, {"type": "stage_skip", "tool": subjack_tool.NAME, "reason": "no subdomains discovered"})

    _emit(on_event, {"type": "stage_start", "tool": nmap_tool.NAME})
    nmap_result = nmap_tool.run(cfg.target, dry_run=cfg.dry_run, mock=cfg.mock, full_ports=cfg.nmap_full)
    results.write_tool_output(run_dir, nmap_tool.NAME, nmap_result)
    ctx.results.append(nmap_result)
    _emit(on_event, _stage_end_event(nmap_result))

    web_ports = nmap_tool.parse_open_web_ports(nmap_result.stdout) if nmap_result.available else []

    if web_ports:
        https_ports = [wp for wp in web_ports if wp[1] == "https"]
        port, scheme = https_ports[0] if https_ports else web_ports[0]
        base_url = _base_url(cfg.target, port, scheme)
        for tool_module in WEB_TOOLS:
            _emit(on_event, {"type": "stage_start", "tool": tool_module.NAME})
            if tool_module in _WORDLIST_TOOLS:
                result = tool_module.run(base_url, dry_run=cfg.dry_run, mock=cfg.mock, wordlist=cfg.gobuster_wordlist)
            else:
                result = tool_module.run(base_url, dry_run=cfg.dry_run, mock=cfg.mock)
            results.write_tool_output(run_dir, tool_module.NAME, result)
            ctx.results.append(result)
            _emit(on_event, _stage_end_event(result))

        if https_ports:
            tls_port, _ = https_ports[0]
            _emit(on_event, {"type": "stage_start", "tool": testssl_tool.NAME})
            testssl_result = testssl_tool.run(cfg.target, port=tls_port, dry_run=cfg.dry_run, mock=cfg.mock)
            results.write_tool_output(run_dir, testssl_tool.NAME, testssl_result)
            ctx.results.append(testssl_result)
            _emit(on_event, _stage_end_event(testssl_result))
        else:
            _emit(on_event, {"type": "stage_skip", "tool": testssl_tool.NAME, "reason": "no https port"})

        screenshot_dir = run_dir / "screenshots"
        _emit(on_event, {"type": "stage_start", "tool": gowitness_tool.NAME})
        gowitness_result = gowitness_tool.run(base_url, screenshot_dir, dry_run=cfg.dry_run, mock=cfg.mock)
        results.write_tool_output(run_dir, gowitness_tool.NAME, gowitness_result)
        ctx.results.append(gowitness_result)
        _emit(on_event, _stage_end_event(gowitness_result))
    else:
        ctx.skip_note = (
            "No open web port detected by nmap -- skipped whatweb/nikto/gobuster/ffuf/"
            "wafw00f/nuclei/getjs/linkfinder/testssl/gowitness."
        )
        for tool_module in (*WEB_TOOLS, testssl_tool, gowitness_tool):
            _emit(on_event, {"type": "stage_skip", "tool": tool_module.NAME, "reason": "no open web port"})

    _emit(on_event, {"type": "stage_start", "tool": "ai_summary"})
    if backend is None:
        if cfg.dry_run:
            backend = DryRunBackend()
        else:
            backend = factory.get_backend(
                cfg.llm_backend,
                ollama_model=cfg.ollama_model,
                ollama_host=cfg.ollama_host,
                claude_model=cfg.claude_model,
            )

    summary_md = markdown_report.build(cfg.target, ctx.results, backend, skip_note=ctx.skip_note)
    ctx.summary_path = run_dir / "summary.md"
    ctx.summary_path.write_text(summary_md)
    _emit(on_event, {"type": "stage_end", "tool": "ai_summary", "available": True, "returncode": 0, "duration_s": 0.0, "skipped_reason": None})

    if cfg.render_pdf:
        ctx.pdf_path = pdf_report.render(summary_md, run_dir / "summary.pdf", cfg.target)

    results.write_manifest(run_dir, cfg.target, ctx.results, llm_backend=backend.name)

    _emit(on_event, {
        "type": "pipeline_end",
        "run_dir": str(run_dir),
        "summary_path": str(ctx.summary_path),
        "pdf_path": str(ctx.pdf_path) if ctx.pdf_path else None,
    })

    return ctx
