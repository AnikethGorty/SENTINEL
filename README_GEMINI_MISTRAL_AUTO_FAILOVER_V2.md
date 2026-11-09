# SENTINEL — Gemini + Mistral automatic failover v2

This is an overlay patch intended to be applied **after** `sentinel-mistral-provider-v1.zip`.
It adds a provider wrapper: Gemini remains the primary provider by default, and Mistral is
attempted automatically when Gemini cannot serve the request.

## Configuration (`.env` at the repository root)

```dotenv
# Primary provider and automatic secondary provider
AI_PROVIDER=gemini
AI_AUTO_FAILOVER=true
AI_FALLBACK_PROVIDER=mistral

# Keep both provider credentials configured
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=gemini-3.7-flash,gemini-3.6-flash
GEMINI_ATTEMPT_TIMEOUT_SECONDS=60

MISTRAL_API_KEY=your_mistral_key
MISTRAL_MODEL=mistral-small-latest
MISTRAL_BASE_URL=https://api.mistral.ai/v1
MISTRAL_TIMEOUT_SECONDS=90
```

To make Mistral primary and Gemini secondary, set `AI_PROVIDER=mistral` and
`AI_FALLBACK_PROVIDER=gemini`. To disable automatic failover, set `AI_AUTO_FAILOVER=false`.

## Failover behavior

- Gemini tries its configured model list first.
- If Gemini exhausts its models or encounters a provider outage, rate limit, timeout,
  unavailable model, or transport failure, the same prompt is attempted with Mistral.
- Successful fallback responses report `provider=mistral`, `fallback_used=true`, and
  include both providers' diagnostics in `failover`.
- Autonomous Assessment logs an `ai_provider_failover` event with the primary failure,
  selected fallback, and iteration number.
- If both providers fail, the API receives a structured `all_providers_failed` diagnostic.
- Invalid Gemini credentials (401/403) and malformed requests (400) are not masked by
  automatic fallback; fix the configuration instead. If the Mistral key is absent or
  invalid, fallback will fail visibly too.
- `AI_PROVIDER` is not rewritten when fallback succeeds. Gemini is tried again on the
  next request, allowing automatic recovery when the outage ends.

Failover only changes which model generates a recommendation. It does not bypass GATE,
human approval, scope validation, signed scanner authorization, or the scanner allowlist.

## Apply the overlay

Back up the existing files first. This patch expects the Mistral v1 patch to already be installed.

```bash
cd ~/Desktop/PROFESSIONAL/sentinel
mkdir -p .sentinel-backups/ai-failover-v2/backend/app/intelligence/providers
cp backend/app/intelligence/providers/factory.py .sentinel-backups/ai-failover-v2/backend/app/intelligence/providers/
cp backend/app/api/advanced.py .sentinel-backups/ai-failover-v2/backend/app/api/
cp docker-compose.yml .sentinel-backups/ai-failover-v2/
unzip -o ~/Downloads/sentinel-gemini-mistral-auto-failover-v2.zip -d .
docker compose up -d --build backend
docker compose logs --tail=120 backend
```

No database migration or volume reset is required. Do not use `docker compose down -v`.

## Verification

```bash
docker compose exec backend sh -lc 'python - <<'PY'
import os
print("Primary:", os.getenv("AI_PROVIDER"))
print("Auto failover:", os.getenv("AI_AUTO_FAILOVER"))
print("Fallback:", os.getenv("AI_FALLBACK_PROVIDER"))
print("Gemini key configured:", bool(os.getenv("GEMINI_API_KEY")))
print("Mistral key configured:", bool(os.getenv("MISTRAL_API_KEY")))
PY'
```

Then use Ask AI in Assessment Operations. The response reports the provider/model actually
used. For autonomous sessions, inspect the event log for `ai_provider_failover`.

## Validation performed for this patch

- Python syntax compilation passed for the new failover wrapper, factory, and patched
  autonomous API module.
- ZIP integrity check passed.
- Live Docker, database, Gemini, and Mistral API calls were not run in this environment.
