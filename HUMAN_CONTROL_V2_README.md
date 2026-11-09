# SENTINEL Human Control Plane v2

## What this patch changes
- Adds `POST /proposals/{proposal_id}/execute`; only the latest APPROVED version with an approval record can be dispatched.
- Rechecks the active scope and reserves rate/concurrency capacity at dispatch time.
- Signs a 60-second, job-bound Ed25519 authorization in the backend.
- Scanner verifies the signature, exact job tuple, issuer/audience, expiry, and consumes a persistent one-time `jti` before executing.
- Direct backend `/scanner/nmap` is disabled (410).
- `/assessment/run` now creates an Nmap proposal and does not execute it.
- Removes scanner host port 8100 publication. Backend reaches scanner over the internal Compose network.

## Apply
1. Back up the project and database first. Do not remove the `sentinel_data` volume.
2. Extract this patch at the repository root, preserving paths.
3. Install cryptography in both images via rebuild.
4. Generate signing keys with `bash scripts/generate-execution-keys.sh` and place both emitted values in `.env`. Keep the private value secret; never commit `.env`.
5. Rebuild/recreate backend and scanner: `docker compose up -d --build backend scanner`.
6. Confirm `docker compose ps`; confirm `docker compose port scanner 8100` prints no host binding.

## API flow
1. Create proposal: `POST /projects/{project_id}/transcripts/{transcript_id}/proposals`.
2. Approve exact version: `POST /proposals/{proposal_id}/decision` with `{"reviewed_by":"...","decision":"APPROVED"}`.
3. Execute: `POST /proposals/{proposal_id}/execute`.

For the assessment helper, `POST /assessment/run` now returns `AWAITING_APPROVAL` and a proposal instead of scanning immediately.

## Important limitations
- This is a development milestone, not production-ready identity or authorization. `reviewed_by` is still caller-supplied because the app has no authentication/RBAC yet. Do not expose the backend API publicly.
- Scanner target policy is still the existing static IP allowlist plus backend scope checks. DNS rebinding/redirect hardening for web tools remains separate work.
- SQLite replay state persists in the existing `scanner_results` named volume. If that volume is deleted, replay history is lost; never delete it casually.
- There is a narrow crash-recovery concern if backend marks a proposal EXECUTING and dies before finishing. Such proposals require operator reconciliation; a later milestone should add leases/recovery.
- Existing historical proposals and scan records are not deleted. `create_all` creates no destructive migration. No DB volume reset is required.
