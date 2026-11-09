from abc import ABC, abstractmethod
from typing import Any


class AIProviderUnavailable(Exception):
    """Raised when an AI provider cannot fulfil a request."""

    def __init__(
        self,
        message: str,
        diagnostics: dict[str, Any] | None = None,
    ):
        self.diagnostics = diagnostics or {}
        super().__init__(message)


class AIProvider(ABC):
    """Common interface for all SENTINEL AI providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_instruction: str,
        max_output_tokens: int = 2048,
    ) -> dict[str, Any]:
        """Generate a structured AI response."""
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        """Release provider resources."""
        raise NotImplementedError
