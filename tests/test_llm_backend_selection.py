from unittest.mock import MagicMock, patch

import httpx
import pytest

from reconai.llm import factory
from reconai.llm.claude_backend import ClaudeBackend
from reconai.llm.ollama_backend import OllamaBackend


def test_factory_returns_ollama_backend():
    backend = factory.get_backend("ollama")
    assert isinstance(backend, OllamaBackend)


def test_factory_returns_claude_backend():
    backend = factory.get_backend("claude")
    assert isinstance(backend, ClaudeBackend)


def test_factory_unknown_backend_raises():
    with pytest.raises(ValueError):
        factory.get_backend("gpt4")


def test_ollama_summarize_extracts_response_text():
    backend = OllamaBackend()
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"response": "  interesting findings here  "}
    with patch("reconai.llm.ollama_backend.httpx.post", return_value=fake_response):
        result = backend.summarize("summarize this")
    assert result == "interesting findings here"


def test_ollama_summarize_connect_error_raises_clear_message():
    backend = OllamaBackend()
    with patch("reconai.llm.ollama_backend.httpx.post", side_effect=httpx.ConnectError("refused")):
        with pytest.raises(RuntimeError, match="ollama serve"):
            backend.summarize("summarize this")


def test_claude_summarize_extracts_text_block():
    backend = ClaudeBackend.__new__(ClaudeBackend)  # skip __init__ (no real API client needed)
    backend.model = "claude-opus-4-8"
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = "  narrative summary  "
    fake_response = MagicMock()
    fake_response.content = [text_block]
    backend.client = MagicMock()
    backend.client.messages.create.return_value = fake_response

    result = backend.summarize("summarize this")
    assert result == "narrative summary"
