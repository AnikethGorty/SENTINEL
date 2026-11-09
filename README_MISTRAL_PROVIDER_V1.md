# SENTINEL — Gemini + Mistral provider configuration

This patch adds Mistral as a second implementation of SENTINEL's existing `AIProvider` interface. Both providers remain available; `AI_PROVIDER` selects the active one. No scanner permissions, GATE checks, approval rules, or execution boundaries are changed.

## Configure the root `.env`

Keep both keys in the local root `.env` (never commit it):

```dotenv
# Choose exactly one active provider: gemini or mistral
AI_PROVIDER=mistral

# Gemini remains configured as an alternate
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=gemini-3.7-flash,gemini-3.6-flash
GEMINI_ATTEMPT_TIMEOUT_SECONDS=60

# Mistral
MISTRAL_API_KEY=your_mistral_key
MISTRAL_MODEL=mistral-small-latest
MISTRAL_BASE_URL=https://api.mistral.ai/v1
MISTRAL_TIMEOUT_SECONDS=90
```

To switch back to Gemini, change only `AI_PROVIDER=gemini` and recreate the backend container.

## Apply

Back up the touched files first, unzip this patch at the repository root, then run:

```bash
mkdir -p .sentinel-backups/mistral-provider-v1
cp docker-compose.yml .sentinel-backups/mistral-provider-v1/
cp backend/app/intelligence/providers/factory.py .sentinel-backups/mistral-provider-v1/
cp backend/app/api/advanced.py .sentinel-backups/mistral-provider-v1/
cp frontend/src/AssessmentWorkspace.tsx .sentinel-backups/mistral-provider-v1/
cp frontend/src/AdvancedFeatures.tsx .sentinel-backups/mistral-provider-v1/
unzip -o ~/Downloads/sentinel-mistral-provider-v1.zip -d .
docker compose up -d --build backend frontend
docker compose logs --tail=120 backend
```

If you only changed the provider selection or API key later, recreate the backend so Compose injects the updated environment:

```bash
docker compose up -d --force-recreate backend
docker compose logs -f --tail=80 backend
```

## Verify Mistral

```bash
docker compose exec backend sh -lc 'python - <<'PY'
import os
print("AI_PROVIDER:", os.getenv("AI_PROVIDER"))
print("MISTRAL_API_KEY configured:", bool(os.getenv("MISTRAL_API_KEY")))
print("MISTRAL_MODEL:", os.getenv("MISTRAL_MODEL"))
PY'
```

Then use **Ask AI** in Assessment Operations. The response shows the actual provider/model and diagnostics. Autonomous scan events now use provider-neutral AI wording. Mistral's JSON mode is requested for planner/copilot responses; the existing backend still validates the returned JSON before creating proposals.

## Notes

- Default model is `mistral-small-latest`; change `MISTRAL_MODEL` if your Mistral account exposes a different model.
- This integration uses Mistral's official `/v1/chat/completions` API through the already-installed `httpx` dependency; no additional Python package is required.
- The Mistral API key is read only by the backend container and is never sent to the browser.
- This patch does not implement automatic Gemini→Mistral failover. It provides an explicit, predictable provider switch via `AI_PROVIDER`.
- The provider still only generates recommendations. Existing human approval and GATE authorization remain mandatory before scanner execution.
