import os

from app.intelligence.providers.base import AIProvider
from app.intelligence.providers.gemini import GeminiProvider


def get_ai_provider() -> AIProvider:
    provider_name = os.getenv(
        "AI_PROVIDER",
        "gemini",
    ).strip().lower()

    if provider_name == "gemini":
        return GeminiProvider()

    raise ValueError(
        f"Unsupported AI provider: {provider_name}"
    )
