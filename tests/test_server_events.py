import asyncio

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
