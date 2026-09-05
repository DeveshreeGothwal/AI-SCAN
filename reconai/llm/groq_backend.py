from __future__ import annotations

import os

import httpx

from .base import LLMBackend

DEFAULT_MODEL = "openai/gpt-oss-120b"  # llama-3.3-70b-versatile was deprecated 2026-06-17
API_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqBackend(LLMBackend):
    """Cloud API, no local model server needed -- and unlike Claude, Groq's
    free tier needs no card and no spend: https://console.groq.com/keys.
    Good fit for a resource-constrained container that also can't run Ollama."""

    name = "groq"

    def __init__(self, model: str | None = None, timeout: float = 60.0):
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout

    def summarize(self, prompt: str, max_tokens: int = 2048) -> str:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY is not set. Get a free key at https://console.groq.com/keys.")

        try:
            resp = httpx.post(
                API_URL,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            raise RuntimeError("Could not reach the Groq API. Check your network connection.") from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise RuntimeError("Groq API authentication failed. Check your GROQ_API_KEY.") from exc
            if exc.response.status_code == 429:
                raise RuntimeError("Groq API rate limit hit. Wait and retry.") from exc
            raise RuntimeError(f"Groq API returned an error: {exc}") from exc

        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
