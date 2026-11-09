import logging
import os
import time
from typing import Any

import httpx

from app.intelligence.providers.base import AIProvider, AIProviderUnavailable

logger = logging.getLogger("sentinel.ai")


class MistralProvider(AIProvider):
    """Mistral chat-completions provider implementing SENTINEL's common interface."""

    def __init__(self) -> None:
        self.api_key = os.getenv("MISTRAL_API_KEY", "").strip()
        if not self.api_key:
            raise RuntimeError("MISTRAL_API_KEY is not configured")
        self.model = os.getenv("MISTRAL_MODEL", "mistral-small-latest").strip()
        self.base_url = os.getenv("MISTRAL_BASE_URL", "https://api.mistral.ai/v1").rstrip("/")
        self.timeout_seconds = float(os.getenv("MISTRAL_TIMEOUT_SECONDS", "90"))
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )

    async def generate(
        self,
        prompt: str,
        system_instruction: str,
        max_output_tokens: int = 2048,
    ) -> dict[str, Any]:
        started = time.monotonic()
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            if response.is_error:
                # Do not include request headers or API key in diagnostics.
                detail = response.text[:1200]
                raise AIProviderUnavailable(
                    f"Mistral API returned HTTP {response.status_code}.",
                    diagnostics={
                        "provider": "mistral",
                        "status": "api_error",
                        "http_status": response.status_code,
                        "message": detail,
                        "model": self.model,
                    },
                )
            data = response.json()
            choices = data.get("choices") or []
            if not choices:
                raise AIProviderUnavailable(
                    "Mistral returned no completion choices.",
                    diagnostics={"provider": "mistral", "status": "empty_response", "model": self.model},
                )
            message = choices[0].get("message") or {}
            content = message.get("content") or ""
            if isinstance(content, list):
                content = "".join(
                    str(part.get("text", "")) if isinstance(part, dict) else str(part)
                    for part in content
                )
            usage = data.get("usage") or {}
            duration = round(time.monotonic() - started, 2)
            logger.info("Mistral succeeded: model=%s duration=%.2fs", data.get("model", self.model), duration)
            return {
                "provider": "mistral",
                "model": data.get("model", self.model),
                "text": str(content),
                "fallback_used": False,
                "attempted_models": 1,
                "usage": {
                    "input_tokens": usage.get("prompt_tokens"),
                    "output_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                },
                "finish_reason": choices[0].get("finish_reason", "UNKNOWN"),
                "diagnostics": {
                    "status": "success",
                    "provider": "mistral",
                    "model": data.get("model", self.model),
                    "duration_seconds": duration,
                    "http_status": response.status_code,
                },
            }
        except AIProviderUnavailable:
            raise
        except httpx.TimeoutException as exc:
            logger.warning("Mistral request timed out after %.2fs", time.monotonic() - started)
            raise AIProviderUnavailable(
                "Mistral request timed out.",
                diagnostics={"provider": "mistral", "status": "timeout", "model": self.model},
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            logger.exception("Mistral request failed")
            raise AIProviderUnavailable(
                "Mistral request failed before a usable response was received.",
                diagnostics={"provider": "mistral", "status": "transport_or_response_error", "model": self.model,
                             "exception_type": type(exc).__name__, "message": str(exc)[:500]},
            ) from exc

    async def close(self) -> None:
        await self.client.aclose()
