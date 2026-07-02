from __future__ import annotations

import httpx

from .base import LLMBackend

DEFAULT_MODEL = "llama3.2:3b"  # ~2GB resident, sized for an 8GB Kali VM
DEFAULT_HOST = "http://localhost:11434"


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(self, model: str | None = None, host: str | None = None, timeout: float = 180.0):
        self.model = model or DEFAULT_MODEL
        self.host = host or DEFAULT_HOST
        self.timeout = timeout

    def preflight(self) -> None:
        """Raise a clear error before the pipeline runs if Ollama/the model isn't ready."""
        try:
            resp = httpx.get(f"{self.host}/api/tags", timeout=5.0)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.host}. Is it running? Try: ollama serve"
            ) from exc

        tags = [m.get("name", "") for m in resp.json().get("models", [])]
        if not any(self.model == t or t.startswith(self.model.split(":")[0]) for t in tags):
            raise RuntimeError(
                f"Model '{self.model}' not found in Ollama. Pull it first: ollama pull {self.model}"
            )

    def summarize(self, prompt: str, max_tokens: int = 2048) -> str:
        try:
            resp = httpx.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": max_tokens, "num_ctx": 4096},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.host}. Is it running? Try: ollama serve"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Ollama returned an error: {exc}") from exc

        data = resp.json()
        return data.get("response", "").strip()
