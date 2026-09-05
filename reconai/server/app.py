from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..config import Config
from ..pipeline import STAGE_ORDER, run_pipeline
from ..report.markdown_report import extract_ai_summary, extract_skip_notes
from ..tools import link_safety_tool
from ..tools.gobuster_tool import WORDLIST_TIERS
from .events import registry

_STATIC_DIR = Path(__file__).parent / "static"
_VALID_TOOL_NAMES = set(STAGE_ORDER) - {"ai_summary"}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    registry.bind_loop(asyncio.get_running_loop())
    yield


app = FastAPI(title="reconai live dashboard", lifespan=_lifespan)


class _BasicAuthMiddleware(BaseHTTPMiddleware):
    """No-op unless DASHBOARD_BASIC_AUTH_USER and DASHBOARD_BASIC_AUTH_PASS are
    both set -- read fresh per-request rather than cached at import time, so a
    local/Kali run with neither var set (the default) is completely
    unaffected, and a public deployment (Render, etc.) can turn this on
    without any code change. Whole-app gate, not per-route: the point is that
    nobody who doesn't already have the password can even see the dashboard
    exists, let alone trigger a scan from it."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/healthz":
            # Render's own health check has no way to send credentials -- without this
            # exemption, a locked-down deployment fails its health check forever and
            # never goes live, even though the app itself is running fine.
            return await call_next(request)

        expected_user = os.environ.get("DASHBOARD_BASIC_AUTH_USER")
        expected_pass = os.environ.get("DASHBOARD_BASIC_AUTH_PASS")
        if not expected_user or not expected_pass:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
            except ValueError:
                decoded = ""
            user, _, password = decoded.partition(":")
            if secrets.compare_digest(user, expected_user) and secrets.compare_digest(password, expected_pass):
                return await call_next(request)
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="reconai"'})


app.add_middleware(_BasicAuthMiddleware)


def _allowed_scan_targets() -> set[str]:
    """Opt-in allowlist for /scan (not /check-link -- that endpoint only ever
    makes one benign GET + a whois lookup against a URL someone hands it,
    nothing port-scan/brute-force-shaped, so there's nothing there for an
    allowlist to protect against). Empty by default (no restriction) unless
    ALLOWED_SCAN_TARGETS is set -- e.g. to a known-safe public test target
    like scanme.nmap.org for a public demo deployment."""
    raw = os.environ.get("ALLOWED_SCAN_TARGETS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


class ScanRequest(BaseModel):
    target: str
    llm_backend: str = "ollama"
    dry_run: bool = False
    mock: bool = False
    nmap_full: bool = False
    wordlist_size: str = "small"
    authorized: bool = False
    proxy: Optional[str] = None
    validate_secrets: bool = False


class LinkCheckRequest(BaseModel):
    url: str
    proxy: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC_DIR / "dashboard.html").read_text()


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.post("/scan")
def start_scan(req: ScanRequest) -> JSONResponse:
    if not req.target.strip():
        return JSONResponse({"error": "target is required"}, status_code=400)
    if not req.authorized:
        return JSONResponse({"error": "you must confirm authorization to scan this target"}, status_code=400)
    allowed_targets = _allowed_scan_targets()
    if allowed_targets and req.target.strip() not in allowed_targets:
        return JSONResponse(
            {"error": f"this deployment only allows scanning: {', '.join(sorted(allowed_targets))}"},
            status_code=400,
        )
    if any(not s.done for s in registry.list_runs()):
        # Each scan runs the full tool chain in its own thread with no cap --
        # verified in practice that a single scan alone can push a 512MB
        # container over its memory limit (github_secrets cloning + scanning a
        # real repo). Concurrent scans would only compound that, so this
        # shared, resource-constrained instance runs one at a time.
        return JSONResponse(
            {"error": "a scan is already running on this shared instance -- wait for it to finish, or check History"},
            status_code=409,
        )
    if req.wordlist_size not in WORDLIST_TIERS:
        return JSONResponse({"error": f"wordlist_size must be one of {list(WORDLIST_TIERS)}"}, status_code=400)

    proxy = (req.proxy or "").strip() or None
    if proxy and not proxy.split("://", 1)[0] in ("socks5", "socks5h", "socks4", "http", "https"):
        return JSONResponse({"error": "proxy must start with socks5://, socks4://, http://, or https://"}, status_code=400)

    run_id = uuid.uuid4().hex[:12]
    registry.create(run_id, req.target)

    def on_event(event: dict) -> None:
        registry.publish(run_id, event)

    def worker() -> None:
        cfg = Config(
            target=req.target,
            llm_backend=req.llm_backend,
            dry_run=req.dry_run,
            mock=req.mock,
            nmap_full=req.nmap_full,
            gobuster_wordlist=WORDLIST_TIERS[req.wordlist_size],
            proxy=proxy,
            validate_secrets=req.validate_secrets,
        )
        try:
            run_pipeline(cfg, on_event=on_event)
        except Exception as exc:  # surfaced to the dashboard rather than swallowed
            registry.publish(run_id, {"type": "pipeline_error", "error": str(exc)})

    threading.Thread(target=worker, daemon=True).start()
    return JSONResponse({"run_id": run_id})


@app.post("/check-link")
def check_link(req: LinkCheckRequest) -> JSONResponse:
    """Standalone link-safety check -- deliberately NOT part of /scan and its
    authorization gate. Checking a URL you received for safety is
    self-protective, not an action against a third party's infrastructure,
    so it runs synchronously with no run_id/event-stream machinery."""
    url = req.url.strip()
    if not url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    proxy = (req.proxy or "").strip() or None
    result = link_safety_tool.run(url, proxy=proxy)
    if not result.available:
        return JSONResponse({"error": result.skipped_reason or "check failed"}, status_code=502)
    return JSONResponse({"url": url, "output": result.stdout})


@app.get("/runs")
def list_runs() -> list[dict]:
    return [
        {"run_id": s.run_id, "target": s.target, "done": s.done, "error": s.error, "started_at": s.started_at}
        for s in registry.list_runs()
    ]


@app.get("/events/{run_id}")
async def stream_events(run_id: str) -> StreamingResponse:
    async def event_stream():
        async for event in registry.subscribe(run_id):
            if event is None:
                yield ": keep-alive\n\n"  # SSE comment -- ignored by EventSource, just keeps bytes flowing
            else:
                yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _run_dir_for(run_id: str) -> Path | None:
    # pipeline_start already carries run_dir, so per-tool output is fetchable
    # as soon as that tool finishes -- no need to wait for the whole scan.
    state = registry.get(run_id)
    if state is None:
        return None
    for event in state.events:
        if event.get("type") in ("pipeline_start", "pipeline_end"):
            return Path(event["run_dir"])
    return None


@app.get("/runs/{run_id}/summary", response_class=PlainTextResponse)
def get_summary(run_id: str) -> PlainTextResponse:
    run_dir = _run_dir_for(run_id)
    if run_dir is None or not (run_dir / "summary.md").exists():
        return PlainTextResponse("not ready", status_code=404)
    return PlainTextResponse((run_dir / "summary.md").read_text())


@app.get("/runs/{run_id}/ai-summary")
def get_ai_summary(run_id: str) -> JSONResponse:
    run_dir = _run_dir_for(run_id)
    if run_dir is None:
        return JSONResponse({"error": "not ready"}, status_code=404)
    ai_summary_path = run_dir / "ai_summary.json"
    if ai_summary_path.exists():
        return JSONResponse(json.loads(ai_summary_path.read_text()))
    # Fall back to extracting from the full report for runs generated before
    # this (small, fast) companion file existed -- reads the potentially
    # large file once, locally, server-side, which is still far cheaper than
    # shipping the whole thing over HTTP to the browser on every page load.
    summary_path = run_dir / "summary.md"
    if not summary_path.exists():
        return JSONResponse({"error": "not ready"}, status_code=404)
    text = summary_path.read_text()
    return JSONResponse({"ai_summary": extract_ai_summary(text), "skip_notes": extract_skip_notes(text)})


@app.get("/runs/{run_id}/impact")
def get_impact(run_id: str) -> JSONResponse:
    run_dir = _run_dir_for(run_id)
    if run_dir is None:
        return JSONResponse({"error": "not ready"}, status_code=404)
    impact_path = run_dir / "impact.json"
    if not impact_path.exists():
        # Predates this feature -- an honest empty state, not a reconstruction attempt.
        return JSONResponse({"findings": [], "score": None, "grade": None, "available": False})
    data = json.loads(impact_path.read_text())
    data["available"] = True
    return JSONResponse(data)


@app.get("/runs/{run_id}/manifest")
def get_manifest(run_id: str) -> JSONResponse:
    run_dir = _run_dir_for(run_id)
    if run_dir is None or not (run_dir / "manifest.json").exists():
        return JSONResponse({"error": "not ready"}, status_code=404)
    return JSONResponse(json.loads((run_dir / "manifest.json").read_text()))


@app.get("/runs/{run_id}/tool/{tool_name}", response_class=PlainTextResponse)
def get_tool_output(run_id: str, tool_name: str) -> PlainTextResponse:
    if tool_name not in _VALID_TOOL_NAMES:
        return PlainTextResponse("unknown tool", status_code=404)
    run_dir = _run_dir_for(run_id)
    if run_dir is None:
        return PlainTextResponse("not ready", status_code=404)
    path = run_dir / f"{tool_name}.txt"
    if not path.exists():
        return PlainTextResponse("not found", status_code=404)
    return PlainTextResponse(path.read_text())


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)
