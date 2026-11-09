# SENTINEL Assessment Operations UI v1

This patch adds the Assessment Operations workspace to the existing React/Vite frontend.

## Files
- `frontend/src/AssessmentWorkspace.tsx` — assessment workspace, transcript selection/creation, initial discovery proposal, manual proposal creation, version revision, approval/rejection, execution, event timeline, and API diagnostics.
- `frontend/src/App.tsx` — adds Assessment Operations navigation and mounts the workspace. Preserves the existing Scope Builder and TIF console.
- `frontend/src/App.css` — styles for the assessment workspace.

## Backend endpoints used
- `GET /projects`
- `GET /projects/{project_id}/scope`
- `GET|POST /projects/{project_id}/transcripts`
- `GET /projects/{project_id}/proposals?transcript_id=...`
- `GET /transcripts/{transcript_id}/events`
- `POST /assessment/run` — creates an initial Nmap service-discovery proposal; it does not execute a scan.
- `POST /projects/{project_id}/transcripts/{transcript_id}/proposals`
- `POST /proposals/{proposal_id}/revise`
- `POST /proposals/{proposal_id}/decision`
- `POST /proposals/{proposal_id}/execute`

## Important behavior
- Proposal approval and execution are separate actions.
- Editing creates a new immutable proposal version. The prior version is superseded and the new version requires a fresh decision.
- Execution is only offered for an approved proposal. The backend re-checks active scope and limits at execution time, then performs signed scanner authorization.
- The UI does not call scanner endpoints directly.
- Errors show HTTP status, field paths and validation messages where available, plus the raw API response for debugging.
- The current `/assessment/run` backend endpoint only creates the initial Nmap proposal. This UI does not claim that an autonomous AI planning loop is connected.

## Apply
From the SENTINEL project root:

```bash
unzip -o ~/Downloads/sentinel-assessment-operations-v1.zip -d .
docker compose build frontend
docker compose up -d frontend
docker compose logs --tail=60 frontend
```

No backend changes, migrations, or volume changes are included.
