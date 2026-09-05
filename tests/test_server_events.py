import asyncio

from reconai.server import events
from reconai.server.events import RunRegistry


def test_subscribe_replays_past_events_then_streams_new_ones():
    async def scenario():
        registry = RunRegistry()
        registry.create("run1", "example.com")
        registry.publish("run1", {"type": "stage_start", "tool": "whois"})
        registry.publish("run1", {"type": "stage_end", "tool": "whois", "available": True})

        collected = []
        async for event in registry.subscribe("run1"):
            collected.append(event)
            if len(collected) == 2:
                registry.publish("run1", {"type": "pipeline_end", "run_dir": "x"})
        return collected

    collected = asyncio.run(scenario())
    assert [e["type"] for e in collected] == ["stage_start", "stage_end", "pipeline_end"]


def test_subscribe_unknown_run_yields_nothing():
    async def scenario():
        registry = RunRegistry()
        return [event async for event in registry.subscribe("does-not-exist")]

    assert asyncio.run(scenario()) == []


def test_publish_marks_run_done_on_pipeline_end():
    registry = RunRegistry()
    state = registry.create("run1", "example.com")
    assert state.done is False
    registry.publish("run1", {"type": "pipeline_end"})
    assert state.done is True


def test_publish_to_unknown_run_is_a_noop():
    registry = RunRegistry()
    registry.publish("does-not-exist", {"type": "stage_start"})  # must not raise


def test_registry_evicts_oldest_completed_runs_over_capacity(monkeypatch):
    # A long-lived dashboard server can run for many hours across many scans
    # -- verified in practice -- so this must not grow without bound.
    monkeypatch.setattr(events, "_MAX_TRACKED_RUNS", 3)
    registry = RunRegistry()
    for i in range(3):
        registry.create(f"run{i}", "example.com")
        registry.publish(f"run{i}", {"type": "pipeline_end", "run_dir": "x"})

    registry.create("run3", "example.com")
    registry.publish("run3", {"type": "pipeline_end", "run_dir": "x"})

    assert registry.get("run0") is None  # oldest completed run evicted
    assert registry.get("run3") is not None
    assert len(registry.list_runs()) == 3


def test_subscribe_yields_heartbeat_during_a_silent_gap(monkeypatch):
    monkeypatch.setattr(events, "_HEARTBEAT_INTERVAL", 0.01)

    async def scenario():
        registry = RunRegistry()
        registry.create("run1", "example.com")

        collected = []
        async for event in registry.subscribe("run1"):
            collected.append(event)
            if len(collected) == 3:
                registry.publish("run1", {"type": "pipeline_end", "run_dir": "x"})
            if len(collected) == 4:
                break
        return collected

    collected = asyncio.run(scenario())
    assert collected[:3] == [None, None, None]
    assert collected[3]["type"] == "pipeline_end"


def test_registry_never_evicts_an_in_progress_run(monkeypatch):
    monkeypatch.setattr(events, "_MAX_TRACKED_RUNS", 2)
    registry = RunRegistry()
    registry.create("still-running", "example.com")  # never published as done

    for i in range(5):
        registry.create(f"run{i}", "example.com")
        registry.publish(f"run{i}", {"type": "pipeline_end", "run_dir": "x"})

    assert registry.get("still-running") is not None
