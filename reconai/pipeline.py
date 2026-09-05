from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import results
from .config import Config
from .llm import factory
from .llm.base import LLMBackend
from .llm.null_backend import DryRunBackend
from .report import impact_analysis, markdown_report, pdf_report
from .tools import (
    auth_audit_tool,
    bucket_enum_tool,
    cors_scan_tool,
    crtsh_tool,
    cve_correlate_tool,
    dns_axfr_tool,
    dns_tool,
    ffuf_tool,
    getjs_tool,
    github_secrets_tool,
    gobuster_tool,
    google_dorks_tool,
    graphql_probe_tool,
    httpx_tool,
    injection_probe_tool,
    linkfinder_tool,
    nikto_tool,
    nmap_tool,
    nuclei_tool,
    privacy_scan_tool,
    secret_scan_tool,
    security_headers_tool,
    sqlmap_tool,
    subfinder_tool,
    subjack_tool,
    testssl_tool,
    theharvester_tool,
    wafw00f_tool,
    waybackurls_tool,
    whatweb_tool,
    whois_tool,
)
from .tools.base import ToolResult, registrable_domain

PASSIVE_TOOLS = (
    whois_tool, dns_tool, dns_axfr_tool, subfinder_tool, crtsh_tool,
    theharvester_tool, google_dorks_tool, bucket_enum_tool, github_secrets_tool,
)
# These query domain-wide passive sources (subfinder's providers, crt.sh's
# certificate-transparency search, theHarvester's OSINT sources, Google
# dorks) -- given the exact scanned hostname when that hostname is itself
# already a subdomain (e.g. "www.example.com"), most of them return nothing,
# since there's no such thing as a sub-subdomain of "www" (and a dork scoped
# to just "www." misses exposures on any other subdomain). Verified for
# real: querying against the registrable/apex domain instead is what
# actually surfaces sibling subdomains. Every other passive tool above
# (whois, dns, dns_axfr, bucket_enum, github_secrets) stays scoped to the
# exact target.
_APEX_DOMAIN_TOOLS = (subfinder_tool, crtsh_tool, theharvester_tool, google_dorks_tool)
# gobuster and ffuf both need a wordlist, handled as a special case below.
WEB_TOOLS = (
    whatweb_tool, nikto_tool, gobuster_tool, ffuf_tool, wafw00f_tool,
    cors_scan_tool, security_headers_tool, auth_audit_tool, privacy_scan_tool,
    nuclei_tool, getjs_tool, linkfinder_tool,
)
_WORDLIST_TOOLS = (gobuster_tool, ffuf_tool)
# Need discovered parameter URLs (from waybackurls), handled as a special case below.
_PARAM_URL_TOOLS = (injection_probe_tool, sqlmap_tool)

# Full set of stages a run can go through, in order. Some are conditionally
# skipped (httpx needs subdomains, the web-only tools need an open web port,
# injection_probe/sqlmap need parameterized URLs from waybackurls).
# A progress UI can use this to render every stage up front as "pending".
STAGE_ORDER = (
    "whois", "dns", "dns_axfr", "subfinder", "crtsh", "theharvester", "google_dorks",
    "bucket_enum", "github_secrets",
    "httpx", "subjack", "waybackurls", "nmap",
    "whatweb", "nikto", "gobuster", "ffuf", "wafw00f", "cors_scan", "security_headers",
    "auth_audit", "privacy_scan", "nuclei", "getjs", "linkfinder",
    "cve_correlate", "secret_scan", "graphql_probe", "injection_probe", "sqlmap",
    "testssl",
    "ai_summary",
)

EventCallback = Callable[[dict], None]


def _emit(on_event: EventCallback | None, event: dict) -> None:
    if on_event is not None:
        on_event(event)


def _skip(ctx: "RunContext", on_event: EventCallback | None, tool: str, reason: str) -> None:
    # Recorded on ctx (not just emitted live) so a skip reason survives into the
    # persisted summary.md -- otherwise anyone reading the report later has no
    # way to tell "we forgot to run this tool" from "we deliberately skipped it".
    _emit(on_event, {"type": "stage_skip", "tool": tool, "reason": reason})
    ctx.skip_notes.append(f"{tool}: skipped -- {reason}.")


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
    skip_notes: list[str] = field(default_factory=list)
    summary_path: Path | None = None
    pdf_path: Path | None = None
    pdf_error: str | None = None


def _base_url(target: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{target}"
    return f"{scheme}://{target}:{port}"


def run_pipeline(cfg: Config, backend: LLMBackend | None = None, on_event: EventCallback | None = None) -> RunContext:
    run_dir = results.make_run_dir(cfg.target)
    ctx = RunContext(target=cfg.target, run_dir=run_dir)
    _emit(on_event, {"type": "pipeline_start", "target": cfg.target, "run_dir": str(run_dir), "stages": list(STAGE_ORDER)})

    passive_domain = registrable_domain(cfg.target)
    if passive_domain != cfg.target:
        apex_tool_names = "/".join(t.NAME for t in _APEX_DOMAIN_TOOLS)
        ctx.skip_notes.append(
            f"{apex_tool_names} queried against the registrable domain '{passive_domain}' "
            f"rather than the exact target '{cfg.target}', since passive subdomain-discovery sources "
            "need the apex domain to return results -- any sibling subdomains they turn up are within "
            "the same authorized organization but outside the literal target hostname"
        )

    for tool_module in PASSIVE_TOOLS:
        _emit(on_event, {"type": "stage_start", "tool": tool_module.NAME})
        tool_target = passive_domain if tool_module in _APEX_DOMAIN_TOOLS else cfg.target
        result = tool_module.run(tool_target, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
        results.write_tool_output(run_dir, tool_module.NAME, result)
        ctx.results.append(result)
        _emit(on_event, _stage_end_event(result))

    subfinder_result = next(r for r in ctx.results if r.tool == subfinder_tool.NAME)
    crtsh_result = next(r for r in ctx.results if r.tool == crtsh_tool.NAME)
    subdomains = sorted(set(
        (subfinder_tool.parse_subdomains(subfinder_result.stdout) if subfinder_result.available else [])
        + (crtsh_tool.parse_subdomains(crtsh_result.stdout) if crtsh_result.available else [])
    ))
    if subdomains:
        _emit(on_event, {"type": "stage_start", "tool": httpx_tool.NAME})
        httpx_result = httpx_tool.run(subdomains, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
        results.write_tool_output(run_dir, httpx_tool.NAME, httpx_result)
        ctx.results.append(httpx_result)
        _emit(on_event, _stage_end_event(httpx_result))

        _emit(on_event, {"type": "stage_start", "tool": subjack_tool.NAME})
        subjack_result = subjack_tool.run(subdomains, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
        results.write_tool_output(run_dir, subjack_tool.NAME, subjack_result)
        ctx.results.append(subjack_result)
        _emit(on_event, _stage_end_event(subjack_result))
    else:
        _skip(ctx, on_event, httpx_tool.NAME, "no subdomains discovered")
        _skip(ctx, on_event, subjack_tool.NAME, "no subdomains discovered")

    # Passive (queries archive.org, never the target) -- doesn't need subdomains
    # or an open web port, so it always runs.
    _emit(on_event, {"type": "stage_start", "tool": waybackurls_tool.NAME})
    wayback_result = waybackurls_tool.run(cfg.target, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
    results.write_tool_output(run_dir, waybackurls_tool.NAME, wayback_result)
    ctx.results.append(wayback_result)
    _emit(on_event, _stage_end_event(wayback_result))
    param_urls = waybackurls_tool.parse_param_urls(wayback_result.stdout) if wayback_result.available else []

    _emit(on_event, {"type": "stage_start", "tool": nmap_tool.NAME})
    nmap_result = nmap_tool.run(cfg.target, dry_run=cfg.dry_run, mock=cfg.mock, full_ports=cfg.nmap_full, proxy=cfg.proxy)
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
                result = tool_module.run(base_url, dry_run=cfg.dry_run, mock=cfg.mock,
                                          wordlist=cfg.gobuster_wordlist, proxy=cfg.proxy)
            else:
                result = tool_module.run(base_url, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
            results.write_tool_output(run_dir, tool_module.NAME, result)
            ctx.results.append(result)
            _emit(on_event, _stage_end_event(result))

        whatweb_result = next(r for r in ctx.results if r.tool == whatweb_tool.NAME)
        _emit(on_event, {"type": "stage_start", "tool": cve_correlate_tool.NAME})
        cve_result = cve_correlate_tool.run(whatweb_result.stdout, nmap_result.stdout, dry_run=cfg.dry_run,
                                            mock=cfg.mock, proxy=cfg.proxy)
        results.write_tool_output(run_dir, cve_correlate_tool.NAME, cve_result)
        ctx.results.append(cve_result)
        _emit(on_event, _stage_end_event(cve_result))

        getjs_result = next(r for r in ctx.results if r.tool == getjs_tool.NAME)
        js_urls = getjs_tool.parse_js_urls(getjs_result.stdout) if getjs_result.available else []
        _emit(on_event, {"type": "stage_start", "tool": secret_scan_tool.NAME})
        secret_result = secret_scan_tool.run(base_url, js_urls, dry_run=cfg.dry_run, mock=cfg.mock,
                                             proxy=cfg.proxy, validate=cfg.validate_secrets)
        results.write_tool_output(run_dir, secret_scan_tool.NAME, secret_result)
        ctx.results.append(secret_result)
        _emit(on_event, _stage_end_event(secret_result))

        linkfinder_result = next(r for r in ctx.results if r.tool == linkfinder_tool.NAME)
        graphql_sources = [
            getjs_result.stdout if getjs_result.available else "",
            linkfinder_result.stdout if linkfinder_result.available else "",
            wayback_result.stdout if wayback_result.available else "",
        ]
        _emit(on_event, {"type": "stage_start", "tool": graphql_probe_tool.NAME})
        graphql_result = graphql_probe_tool.run(base_url, graphql_sources, dry_run=cfg.dry_run,
                                                 mock=cfg.mock, proxy=cfg.proxy)
        results.write_tool_output(run_dir, graphql_probe_tool.NAME, graphql_result)
        ctx.results.append(graphql_result)
        _emit(on_event, _stage_end_event(graphql_result))

        if param_urls:
            for tool_module in _PARAM_URL_TOOLS:
                _emit(on_event, {"type": "stage_start", "tool": tool_module.NAME})
                result = tool_module.run(param_urls, dry_run=cfg.dry_run, mock=cfg.mock, proxy=cfg.proxy)
                results.write_tool_output(run_dir, tool_module.NAME, result)
                ctx.results.append(result)
                _emit(on_event, _stage_end_event(result))
        else:
            for tool_module in _PARAM_URL_TOOLS:
                _skip(ctx, on_event, tool_module.NAME, "no parameterized URLs discovered")

        if https_ports:
            tls_port, _ = https_ports[0]
            _emit(on_event, {"type": "stage_start", "tool": testssl_tool.NAME})
            testssl_result = testssl_tool.run(cfg.target, port=tls_port, dry_run=cfg.dry_run,
                                               mock=cfg.mock, proxy=cfg.proxy)
            results.write_tool_output(run_dir, testssl_tool.NAME, testssl_result)
            ctx.results.append(testssl_result)
            _emit(on_event, _stage_end_event(testssl_result))
        else:
            _skip(ctx, on_event, testssl_tool.NAME, "no https port")
    else:
        for tool_module in (*WEB_TOOLS, cve_correlate_tool, secret_scan_tool, graphql_probe_tool,
                             *_PARAM_URL_TOOLS, testssl_tool):
            _skip(ctx, on_event, tool_module.NAME, "no open web port detected by nmap")

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
                groq_model=cfg.groq_model,
            )

    summary_md = markdown_report.build(cfg.target, ctx.results, backend, skip_notes=ctx.skip_notes)
    ctx.summary_path = run_dir / "summary.md"
    ctx.summary_path.write_text(summary_md)
    results.write_ai_summary(run_dir, markdown_report.extract_ai_summary(summary_md), ctx.skip_notes)
    _emit(on_event, {"type": "stage_end", "tool": "ai_summary", "available": True, "returncode": 0, "duration_s": 0.0, "skipped_reason": None})

    impact_findings = impact_analysis.analyze(ctx.results)
    score, grade = impact_analysis.compute_score(impact_findings)
    results.write_impact_analysis(run_dir, impact_findings, score, grade)

    if cfg.render_pdf:
        try:
            ctx.pdf_path = pdf_report.render(summary_md, run_dir / "summary.pdf", cfg.target)
        except Exception as exc:  # noqa: BLE001 -- a bonus export failing must not erase an
            # otherwise-successful scan (summary.md is already written above at this point).
            ctx.pdf_error = str(exc)

    results.write_manifest(run_dir, cfg.target, ctx.results, llm_backend=backend.name)

    _emit(on_event, {
        "type": "pipeline_end",
        "run_dir": str(run_dir),
        "summary_path": str(ctx.summary_path),
        "pdf_path": str(ctx.pdf_path) if ctx.pdf_path else None,
    })

    return ctx
