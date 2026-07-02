from abc import ABC, abstractmethod


class LLMBackend(ABC):
    name: str

    @abstractmethod
    def summarize(self, prompt: str, max_tokens: int = 2048) -> str:
        """Send prompt, return the model's text response."""
        raise NotImplementedError
