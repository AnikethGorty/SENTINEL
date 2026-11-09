import os

from app.intelligence.providers.base import AIProvider
from app.intelligence.providers.gemini import GeminiProvider
from app.intelligence.providers.mistral import MistralProvider


def get_ai_provider() -> AIProvider:
    """Create the provider selected by AI_PROVIDER (gemini or mistral)."""
    provider_name = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    if provider_name == "gemini":
        return GeminiProvider()
    if provider_name == "mistral":
        return MistralProvider()
    raise ValueError(
        f"Unsupported AI_PROVIDER '{provider_name}'. Choose 'gemini' or 'mistral'."
    )
