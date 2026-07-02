from __future__ import annotations

import asyncio
import json
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from ..config import Config
from ..pipeline import STAGE_ORDER, run_pipeline
from ..tools.gobuster_tool import WORDLIST_TIERS
from .events import registry

_STATIC_DIR = Path(__file__).parent / "static"
_VALID_TOOL_NAMES = set(STAGE_ORDER) - {"ai_summary"}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    registry.bind_loop(asyncio.get_running_loop())
    yield


app = FastAPI(title="reconai live dashboard", lifespan=_lifespan)


class ScanRequest(BaseModel):
    target: str
    llm_backend: str = "ollama"
    dry_run: bool = False
    mock: bool = False
    nmap_full: bool = False
    wordlist_size: str = "small"
    authorized: bool = False


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC_DIR / "dashboard.html").read_text()


@app.post("/scan")
def start_scan(req: ScanRequest) -> JSONResponse:
    if not req.target.strip():
        return JSONResponse({"error": "target is required"}, status_code=400)
    if not req.authorized:
        return JSONResponse({"error": "you must confirm authorization to scan this target"}, status_code=400)
    if req.wordlist_size not in WORDLIST_TIERS:
        return JSONResponse({"error": f"wordlist_size must be one of {list(WORDLIST_TIERS)}"}, status_code=400)

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
        )
        try:
            run_pipeline(cfg, on_event=on_event)
        except Exception as exc:  # surfaced to the dashboard rather than swallowed
            registry.publish(run_id, {"type": "pipeline_error", "error": str(exc)})

    threading.Thread(target=worker, daemon=True).start()
    return JSONResponse({"run_id": run_id})


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


@app.get("/runs/{run_id}/screenshot")
def get_screenshot(run_id: str):
    run_dir = _run_dir_for(run_id)
    screenshot_dir = run_dir / "screenshots" if run_dir else None
    shots = sorted(screenshot_dir.glob("*")) if screenshot_dir and screenshot_dir.exists() else []
    if not shots:
        return JSONResponse({"error": "no screenshot"}, status_code=404)
    return FileResponse(shots[-1])


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)
