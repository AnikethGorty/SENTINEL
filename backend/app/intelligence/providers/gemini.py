import asyncio
import logging
import os
import time
from app.intelligence.providers.base import AIProvider, AIProviderUnavailable
from typing import Any

from google import genai
from google.genai import errors, types


logger = logging.getLogger("sentinel.ai")


class AllModelsUnavailable(AIProviderUnavailable):
    """Raised when no configured Gemini model can serve a request."""

    def __init__(
        self,
        failures: list[dict[str, Any]],
        total_duration_seconds: float = 0,
    ):
        self.failures = failures
        self.total_duration_seconds = total_duration_seconds

        super().__init__(
            "All configured Gemini models are unavailable."
        )


class GeminiProvider(AIProvider):

    RETRYABLE_STATUS_CODES = {500, 502, 503, 504}

    def __init__(self):

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        primary = os.getenv(
            "GEMINI_MODEL",
            "gemini-3.8-flash"
        )

        fallback_string = os.getenv(
            "GEMINI_FALLBACK_MODELS",
            "gemini-3.7-flash,gemini-3.6-flash"
        )

        fallbacks = [
            model.strip()
            for model in fallback_string.split(",")
            if model.strip()
        ]

        self.models = list(
            dict.fromkeys([primary, *fallbacks])
        )

        # Maximum wall-clock time for an individual model attempt.
        self.attempt_timeout = float(
            os.getenv("GEMINI_ATTEMPT_TIMEOUT_SECONDS", "60")
        )

        self.client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=int(self.attempt_timeout * 1000),
                retry_options=types.HttpRetryOptions(
                    attempts=1,
                ),
            ),
        )

    async def generate(
        self,
        prompt: str,
        system_instruction: str,
        max_output_tokens: int = 2048,
    ) -> dict:

        failures = []
        attempts = []

        overall_started = time.monotonic()

        for index, model in enumerate(self.models):

            attempt_started = time.monotonic()

            logger.info(
                "Gemini attempt %s/%s: model=%s",
                index + 1,
                len(self.models),
                model,
            )

            try:

                response = await asyncio.wait_for(
                    self.client.aio.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            temperature=0.2,
                            max_output_tokens=max_output_tokens,
                            response_mime_type="application/json",
                        ),
                    ),
                    timeout=self.attempt_timeout,
                )

                duration = time.monotonic() - attempt_started
                candidate = (
                    response.candidates[0]
                    if response.candidates
                    else None
                )

                finish_reason = (
                    str(candidate.finish_reason)
                    if candidate and candidate.finish_reason
                    else "UNKNOWN"
                )


                usage = response.usage_metadata

                usage_data = {
                    "input_tokens": (
                        usage.prompt_token_count if usage else None
                    ),
                    "output_tokens": (
                        usage.candidates_token_count if usage else None
                    ),
                    "cached_tokens": (
                        usage.cached_content_token_count if usage else None
                    ),
                }

                attempt_record = {
                    "model": model,
                    "status": "success",
                    "duration_seconds": round(duration, 2),
                    "http_status": None,
                    "finish_reason": finish_reason
                }

                attempts.append(attempt_record)

                logger.info(
                    "Gemini succeeded: model=%s duration=%.2fs",
                    model,
                    duration,
                )

                return {
                    "provider": "gemini",
                    "model": model,
                    "text": response.text or "",
                    "fallback_used": index > 0,
                    "attempted_models": len(attempts),
                    "usage": usage_data,
                    "finish_reason": finish_reason,
                    "diagnostics": {
                        "status": "success",
                        "attempts": attempts,
                        "total_duration_seconds": round(
                            time.monotonic() - overall_started, 2
                        ),
                    },
                }

            except errors.APIError as exc:

                duration = time.monotonic() - attempt_started
                status = getattr(exc, "code", None)

                failure = {
                    "model": model,
                    "status": "api_error",
                    "http_status": status,
                    "duration_seconds": round(duration, 2),
                    "message": str(exc)[:300],
                }

                failures.append(failure)
                attempts.append(failure)

                logger.warning(
                    "Gemini API failure: model=%s status=%s duration=%.2fs",
                    model,
                    status,
                    duration,
                )

                # These are configuration/request problems.
                # Switching models will not fix them.
                if status in {400, 401, 403}:
                    raise

                # A project-level rate limit is unlikely to be solved
                # by trying more models.
                if status == 429:
                    break

                if status in self.RETRYABLE_STATUS_CODES or status == 404:
                    continue

                break

            except (asyncio.TimeoutError, TimeoutError) as exc:

                duration = time.monotonic() - attempt_started

                failure = {
                    "model": model,
                    "status": "timeout",
                    "http_status": None,
                    "duration_seconds": round(duration, 2),
                    "message": str(exc)[:300] or "Attempt timed out",
                }

                failures.append(failure)
                attempts.append(failure)

                logger.warning(
                    "Gemini timed out: model=%s duration=%.2fs",
                    model,
                    duration,
                )

                continue

            except Exception as exc:

                duration = time.monotonic() - attempt_started

                # Some underlying HTTP transport exceptions are exposed
                # by the SDK rather than as asyncio.TimeoutError.
                exception_name = type(exc).__name__

                if "timeout" in exception_name.lower():

                    failure_status = "timeout"

                else:

                    failure_status = "unexpected_error"

                failure = {
                    "model": model,
                    "status": failure_status,
                    "http_status": None,
                    "duration_seconds": round(duration, 2),
                    "exception_type": exception_name,
                    "message": str(exc)[:300],
                }

                failures.append(failure)
                attempts.append(failure)

                logger.exception(
                    "Unexpected Gemini failure: model=%s",
                    model,
                )

                # Try the next model rather than destroying the
                # assessment because of a provider-side failure.
                continue

        total_duration = time.monotonic() - overall_started

        logger.error(
            "All Gemini models unavailable. Attempts=%s duration=%.2fs",
            len(attempts),
            total_duration,
        )

        raise AllModelsUnavailable(
            failures=failures,
            total_duration_seconds=total_duration,
        )

    async def close(self):

        try:
            await self.client.aio.aclose()

        except Exception:
            logger.exception("Failed to close Gemini client")
