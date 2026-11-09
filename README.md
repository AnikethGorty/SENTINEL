# SENTINEL AI Investigation Loop v1

This patch connects completed scanner executions to the existing Gemini provider and human approval queue.

## What it adds

- `POST /assessment/next-step`: submits a completed execution result to the configured AI provider.
- Validates project/transcript and requires an active scope.
- Rechecks that the requested target is included and not excluded by the active scope.
- Supplies Gemini only capabilities also permitted by the active scope and supported by this planner version (`nmap.service_discovery`, `httpx.web_probe`).
- Treats scanner output as untrusted evidence, caps evidence at 100 KB, limits output to five actions, fixes the target to the executed target, and restricts proposed ports to observed open ports.
- Converts accepted AI recommendations into ordinary `origin=AI` proposals. They are not approved or executed.
- Adds an append-only `assessment.ai_analysis_completed` transcript event with summary, observations, provider/model and diagnostics.
- Adds a UI button after successful execution: **Analyse results & propose next steps**.

## Apply

From the project root:

```bash
unzip -o ~/Downloads/sentinel-ai-investigation-loop-v1.zip -d .
docker compose build backend frontend
docker compose up -d backend frontend
docker compose logs --tail=100 backend
```

No database migration or volume deletion is required. The patch adds no tables.

## API request

```json
{
  "project_id": "<project UUID>",
  "transcript_id": "<transcript UUID>",
  "target": "192.168.56.101",
  "requested_by": "operator",
  "execution_result": {"scanner_result": "..."}
}
```

The UI sends the complete response returned by the existing proposal execution endpoint.

## Important constraints / current limitations

- This is a human-in-the-loop planning cycle, not an unattended autonomous scanner.
- Gemini can recommend only the two capability identifiers currently advertised by this planner: `nmap.service_discovery` and `httpx.web_probe`, and only when those operations are allowed by the active scope. The scanner's own typed parameter validation and GATE remain authoritative at execution.
- Follow-up `ports`, when supplied, must be a subset of open ports extracted from structured scanner evidence. The target cannot be changed by Gemini.
- The endpoint stores analysis and proposals, not a durable separate AI-plan object. Provider diagnostics are included in the response and transcript event.
- The current backend has caller-supplied reviewer labels and no full authentication/RBAC; this patch does not change that.
- Full Docker Compose build and live Gemini call must be verified in the user's environment. Python syntax compilation passed locally; no live provider credentials are available here.
