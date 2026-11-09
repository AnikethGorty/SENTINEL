# SENTINEL Gemini Copilot + Scanner Contract Repair

## Changes
- Adds `POST /assessment/assist` to send assessment evidence, an operator message, and/or a scanner execution error to the configured AI provider.
- Adds strict server-side action validation before any Gemini recommendation becomes a proposal.
- Documents the exact scanner contracts: `httpx.web_probe` accepts exactly `{"url": "<absolute URL>"}`; `nmap.service_discovery` accepts only `ports` and `excluded_ports`.
- Requires the HTTP URL hostname to equal the authorized proposal target. Multiple HTTP ports must be separate URL proposals.
- Adds a dashboard copilot text box and an Analyse latest result action.
- Automatically forwards an execution failure and the original proposal details to Gemini with a repair instruction. Corrected actions, if any, enter the existing approval queue; nothing executes automatically.

## Apply
From the repository root:

```bash
unzip -o sentinel-gemini-copilot-repair-v1.zip -d .
docker compose build backend frontend
docker compose up -d backend frontend
docker compose logs --tail=100 backend
```

No database schema changes or volume operations are required.

## API
`POST /assessment/assist`

```json
{
  "project_id": "...",
  "transcript_id": "...",
  "target": "192.168.56.101",
  "user_message": "Fix this execution error",
  "execution_result": null,
  "error_context": {
    "proposal": {"tool":"httpx","action":"web_probe","target":"192.168.56.101","parameters":{"ports":[80,8180]}},
    "failure": {"status":502,"message":"Scanner returned HTTP 400", "response":{"detail":"This operation accepts only the 'url' parameter"}}
  }
}
```

The response contains assistant text, observations, provider diagnostics and newly created proposals. Gemini cannot execute actions; every proposal remains `PROPOSED` until human approval and the normal execution/GATE path.
