from __future__ import annotations

import anthropic

from .base import LLMBackend

DEFAULT_MODEL = "claude-opus-4-8"


class ClaudeBackend(LLMBackend):
    name = "claude"

    def __init__(self, model: str | None = None):
        self.model = model or DEFAULT_MODEL
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    def summarize(self, prompt: str, max_tokens: int = 2048) -> str:
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.AuthenticationError as exc:
            raise RuntimeError(
                "Claude API authentication failed. Check your ANTHROPIC_API_KEY."
            ) from exc
        except anthropic.RateLimitError as exc:
            raise RuntimeError("Claude API rate limit hit. Wait and retry.") from exc
        except anthropic.APIConnectionError as exc:
            raise RuntimeError("Could not reach the Claude API. Check your network connection.") from exc

        for block in response.content:
            if block.type == "text":
                return block.text.strip()
        return ""
