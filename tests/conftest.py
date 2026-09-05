import pytest

from reconai.server.events import registry


@pytest.fixture(autouse=True)
def _reset_shared_run_registry():
    """`reconai.server.events.registry` is a module-level singleton imported by
    reference in reconai/server/app.py, so without this it leaks state between
    tests -- e.g. test_run_dir_resolves_from_pipeline_start_before_scan_finishes
    deliberately leaves a run in "not done" state (no pipeline_end published)
    for the rest of the session, which would wrongly trip a single-scan-at-a-time
    check in every /scan test that runs afterward."""
    registry._runs.clear()
    yield
    registry._runs.clear()
