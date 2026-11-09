# SENTINEL TIF Frontend Console

This patch adds a Tool Integration Framework console to the existing React/Vite frontend while preserving the existing Projects & Scope builder.

## Files changed
- `frontend/src/App.tsx` — adds the TIF catalogue, manifest registration, detail/version view, capability explorer, API diagnostics, and navigation to the existing scope builder.
- `frontend/src/App.css` — adds responsive styling for the TIF console.

No backend files, database tables, Docker configuration, or scanner execution behavior are changed.

## Features
- Integration list with search and selection.
- Registration through pasted YAML or `.yaml` / `.yml` upload.
- Uses the backend's actual request contract: `manifest_yaml` and `created_by`.
- Displays current manifest, immutable SHA-256 digest, validation states, and version history.
- Capability explorer reflects the current backend behavior (only enabled integrations are returned).
- Enable remains visibly unavailable while the isolated runner is not configured; disable is offered only if the backend reports an integration enabled.
- HTTP status, backend detail, Pydantic validation locations/messages, raw response, and suggested fixes are surfaced.
- Network/API connection errors include the configured API base URL and recovery hints.

## Apply
From the SENTINEL project root:

```bash
unzip -o ~/Downloads/sentinel-tif-frontend-v1.zip -d .
docker compose build frontend
docker compose up -d frontend
docker compose logs --tail=50 frontend
```

Open `http://localhost:5173`.

If the frontend is served from a different host, set `VITE_API_BASE_URL` to an API URL reachable from the user's browser and rebuild the frontend. The existing default is `http://localhost:8000`.

## Important
This is a frontend-only patch. It does not add a YAML parser in the browser; the backend remains authoritative for YAML/schema validation. Registration stores a manifest and does not pull or execute its image. Container execution remains blocked until the isolated runner and runtime validation are implemented.
