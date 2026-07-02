from .base import LLMBackend


class DryRunBackend(LLMBackend):
    """Used for --dry-run: no network/model calls, matches the 'nothing real happens' contract."""

    name = "dry-run"

    def summarize(self, prompt: str, max_tokens: int = 2048) -> str:
        return "[DRY-RUN] AI summarization skipped -- no LLM was called."
