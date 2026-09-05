from __future__ import annotations

from .base import LLMBackend
from .claude_backend import ClaudeBackend
from .groq_backend import GroqBackend
from .ollama_backend import OllamaBackend


def get_backend(name: str, *, ollama_model: str | None = None, ollama_host: str | None = None,
                 claude_model: str | None = None, groq_model: str | None = None) -> LLMBackend:
    if name == "ollama":
        return OllamaBackend(model=ollama_model, host=ollama_host)
    if name == "claude":
        return ClaudeBackend(model=claude_model)
    if name == "groq":
        return GroqBackend(model=groq_model)
    raise ValueError(f"Unknown LLM backend: {name!r}. Choose 'ollama', 'claude', or 'groq'.")
