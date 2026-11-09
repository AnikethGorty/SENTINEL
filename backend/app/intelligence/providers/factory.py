import os

from app.intelligence.providers.base import AIProvider
from app.intelligence.providers.failover import FailoverProvider
from app.intelligence.providers.gemini import GeminiProvider
from app.intelligence.providers.mistral import MistralProvider


def get_ai_provider() -> AIProvider:
    """Return configured primary provider with optional secondary failover.

    Defaults to Gemini -> Mistral. Set AI_AUTO_FAILOVER=false to disable.
    Setting AI_PROVIDER=mistral makes Mistral primary; AI_FALLBACK_PROVIDER=gemini
    can optionally enable the reverse direction.
    """
    primary_name = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    auto_failover = os.getenv("AI_AUTO_FAILOVER", "true").strip().lower() in {"1", "true", "yes", "on"}
    fallback_name = os.getenv("AI_FALLBACK_PROVIDER", "mistral").strip().lower()

    factories = {
        "gemini": GeminiProvider,
        "mistral": MistralProvider,
    }
    if primary_name not in factories:
        raise ValueError(f"Unsupported AI_PROVIDER '{primary_name}'. Choose 'gemini' or 'mistral'.")
    if not auto_failover:
        return factories[primary_name]()
    if fallback_name not in factories:
        raise ValueError(f"Unsupported AI_FALLBACK_PROVIDER '{fallback_name}'. Choose 'gemini' or 'mistral'.")
    if fallback_name == primary_name:
        return factories[primary_name]()
    return FailoverProvider(
        primary_name=primary_name,
        primary_factory=factories[primary_name],
        fallback_name=fallback_name,
        fallback_factory=factories[fallback_name],
    )
