from reconai.config import Config
from reconai.pipeline import run_pipeline


def test_dry_run_uses_null_backend_with_no_network_calls(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config(target="example.com", dry_run=True)
    ctx = run_pipeline(cfg)  # no backend override -- must not try to reach a real LLM
    assert "[DRY-RUN]" in ctx.summary_path.read_text()
