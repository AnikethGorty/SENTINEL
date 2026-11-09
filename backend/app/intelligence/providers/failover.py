"""Primary/secondary AI provider failover for SENTINEL.

Only provider-generation failures trigger fallback. Validation, policy, GATE,
and scanner execution remain outside this class and are never bypassed.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

from app.intelligence.providers.base import AIProvider, AIProviderUnavailable

logger = logging.getLogger("sentinel.ai")


class FailoverProvider(AIProvider):
    def __init__(
        self,
        primary_name: str,
        primary_factory: Callable[[], AIProvider],
        fallback_name: str | None = None,
        fallback_factory: Callable[[], AIProvider] | None = None,
    ) -> None:
        self.primary_name = primary_name
        self.primary_factory = primary_factory
        self.fallback_name = fallback_name
        self.fallback_factory = fallback_factory
        self._instances: list[AIProvider] = []
        self.model = None

    async def generate(
        self,
        prompt: str,
        system_instruction: str,
        max_output_tokens: int = 2048,
    ) -> dict[str, Any]:
        primary = None
        primary_started = time.monotonic()
        try:
            primary = self.primary_factory()
            self._instances.append(primary)
            result = await primary.generate(prompt, system_instruction, max_output_tokens)
            result.setdefault("fallback_used", False)
            result.setdefault("failover", {"attempted": False, "primary_provider": self.primary_name})
            self.model = result.get("model")
            return result
        except Exception as primary_exc:
            # Do not conceal invalid credentials or malformed requests. The Gemini
            # adapter may raise SDK auth/config errors directly rather than wrapping them.
            status = getattr(primary_exc, "code", None)
            if status in {400, 401, 403}:
                logger.error("Primary AI provider %s rejected the request (HTTP %s); not failing over", self.primary_name, status)
                raise
            if not self.fallback_name or not self.fallback_factory:
                raise
            if isinstance(primary_exc, (KeyboardInterrupt, SystemExit)):
                raise

            primary_diagnostics = getattr(primary_exc, "diagnostics", None)
            if primary_diagnostics is None:
                primary_diagnostics = {
                    "provider": self.primary_name,
                    "exception_type": type(primary_exc).__name__,
                    "message": str(primary_exc)[:500],
                }
            elapsed = round(time.monotonic() - primary_started, 2)
            logger.warning(
                "AI failover: primary provider %s failed after %.2fs; switching to %s (%s)",
                self.primary_name, elapsed, self.fallback_name, type(primary_exc).__name__,
            )

        fallback = None
        fallback_started = time.monotonic()
        try:
            fallback = self.fallback_factory()
            self._instances.append(fallback)
            result = await fallback.generate(prompt, system_instruction, max_output_tokens)
            diagnostics = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
            result["fallback_used"] = True
            result["failover"] = {
                "attempted": True,
                "succeeded": True,
                "primary_provider": self.primary_name,
                "fallback_provider": self.fallback_name,
                "primary_failure": primary_diagnostics,
                "fallback_duration_seconds": round(time.monotonic() - fallback_started, 2),
            }
            diagnostics["failover"] = result["failover"]
            result["diagnostics"] = diagnostics
            self.model = result.get("model")
            logger.info("AI failover succeeded: %s -> %s (model=%s)", self.primary_name, self.fallback_name, self.model)
            return result
        except Exception as fallback_exc:
            fallback_diagnostics = getattr(fallback_exc, "diagnostics", None) or {
                "provider": self.fallback_name,
                "exception_type": type(fallback_exc).__name__,
                "message": str(fallback_exc)[:500],
            }
            logger.exception("Both AI providers failed: primary=%s fallback=%s", self.primary_name, self.fallback_name)
            raise AIProviderUnavailable(
                f"Primary AI provider {self.primary_name} failed and fallback provider {self.fallback_name} also failed.",
                diagnostics={
                    "status": "all_providers_failed",
                    "primary_provider": self.primary_name,
                    "primary_failure": primary_diagnostics,
                    "fallback_provider": self.fallback_name,
                    "fallback_failure": fallback_diagnostics,
                },
            ) from fallback_exc

    async def close(self) -> None:
        # Close each instantiated adapter once, even if fallback was not needed.
        instances, self._instances = self._instances, []
        seen: set[int] = set()
        for instance in instances:
            if id(instance) in seen:
                continue
            seen.add(id(instance))
            try:
                await instance.close()
            except Exception:
                logger.exception("Failed to close AI provider adapter %s", type(instance).__name__)
