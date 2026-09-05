from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field


@dataclass
class RunState:
    run_id: str
    target: str
    started_at: float = field(default_factory=time.time)
    events: list[dict] = field(default_factory=list)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    done: bool = False
    error: bool = False


_MAX_TRACKED_RUNS = 200
_HEARTBEAT_INTERVAL = 15.0


class RunRegistry:
    """Tracks in-progress/completed scan runs and fans out their events to any
    number of SSE subscribers, including ones that connect after the run started
    (they get replayed the events-so-far first).

    This lives entirely in memory for the life of the server process --
    verified in practice that a dashboard server can stay up continuously for
    many hours across many scans, so without a cap this would grow without
    bound. Bounded to the most recent _MAX_TRACKED_RUNS, evicting the oldest
    *completed* runs first (an in-progress run is never evicted, however old
    its start time, since that would break anyone still watching it)."""

    def __init__(self) -> None:
        self._runs: dict[str, RunState] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _make_room_for_one_more(self) -> None:
        if len(self._runs) < _MAX_TRACKED_RUNS:
            return
        evictable = sorted(
            (s for s in self._runs.values() if s.done),
            key=lambda s: s.started_at,
        )
        # Evict enough completed runs that inserting one more still leaves us
        # at (not over) the cap. If every tracked run happens to be
        # in-progress, this can still exceed the cap -- correctness for
        # anyone actively watching a run matters more than a hard ceiling in
        # that (very unlikely, for a single-user local tool) edge case.
        overage = len(self._runs) - _MAX_TRACKED_RUNS + 1
        for state in evictable[:overage]:
            del self._runs[state.run_id]

    def create(self, run_id: str, target: str) -> RunState:
        self._make_room_for_one_more()
        state = RunState(run_id=run_id, target=target)
        self._runs[run_id] = state
        return state

    def get(self, run_id: str) -> RunState | None:
        return self._runs.get(run_id)

    def list_runs(self) -> list[RunState]:
        return sorted(self._runs.values(), key=lambda s: s.started_at, reverse=True)

    def publish(self, run_id: str, event: dict) -> None:
        """Thread-safe: call this from the pipeline's worker thread."""
        state = self._runs.get(run_id)
        if state is None:
            return
        state.events.append(event)
        if event.get("type") in ("pipeline_end", "pipeline_error"):
            state.done = True
        if event.get("type") == "pipeline_error":
            state.error = True
        for queue in list(state.subscribers):
            if self._loop is not None:
                self._loop.call_soon_threadsafe(queue.put_nowait, event)
            else:
                queue.put_nowait(event)

    async def subscribe(self, run_id: str) -> AsyncIterator[dict | None]:
        """Yields real events as they publish, plus a `None` heartbeat every
        _HEARTBEAT_INTERVAL seconds of silence. Without this, a slow stage (an
        unauthenticated GitHub API call comfortably clearing a minute, say)
        leaves the connection with no bytes flowing for that whole stretch --
        long enough that a reverse proxy in front of the app (verified in
        practice against Render's) treats it as idle and kills it, even though
        the scan itself is still running fine server-side."""
        state = self._runs.get(run_id)
        if state is None:
            return
        queue: asyncio.Queue = asyncio.Queue()
        for past_event in state.events:
            queue.put_nowait(past_event)
        state.subscribers.append(queue)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                except asyncio.TimeoutError:
                    yield None
                    continue
                yield event
                if event.get("type") in ("pipeline_end", "pipeline_error"):
                    break
        finally:
            state.subscribers.remove(queue)


registry = RunRegistry()
