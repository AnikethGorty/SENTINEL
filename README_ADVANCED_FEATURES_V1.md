# SENTINEL Advanced Features v1

This patch adds three operator-controlled capabilities to the existing SENTINEL source tree.

## 1. Optional CPE/CVE enrichment

- `POST /assessment/cpe/compare` calls the existing `cpe_matcher.compare_cpes` function for a CPE 2.3 criterion and an observed CPE.
- `POST /assessment/enrich` explicitly runs the existing deterministic `enrich_services` evaluator on supplied Nmap XML or service observations.
- The Assessment Operations screen adds **Run optional CPE/CVE enrichment** after an execution with Nmap XML output.
- Enrichment is not automatic. The operator must separately click **Send enriched evidence to Gemini**. The `/assessment/assist` request now accepts optional `vulnerability_context`; when omitted, no enrichment is assumed.

Important: the existing `vulnerability_intel.py` evaluator is a curated prototype, not a full implementation of NVD CPE applicability semantics. A candidate is not proof of exploitability or a confirmed vulnerability. The direct CPE matcher compares CPE 2.3 names; version ranges and configuration prerequisites remain separate evaluations.

## 2. VDP-style report review

- `POST /reports/drafts` creates a report draft from manually enriched service data.
- Each generated section is a separate component with `PENDING`, `ACCEPTED`, `EDITED`, or `REMOVED` status.
- Components include executive summary, scope, finding title, affected asset, classification/applicability, technical details, reproduction/PoC, impact, remediation, references, and limitations.
- `POST /reports/{id}/components/{component_id}/decision` records the operator's decision.
- Final approval is blocked while any component remains pending.
- `POST /reports/{id}/approve` locks the approved version.
- `GET /reports/{id}/download` produces a PDF containing accepted/edited components only. Removed components remain in the draft audit data but are excluded from the final PDF.

The report intentionally leaves CVSS, impact, reproduction, remediation and references as unverified/review-required when the input evidence does not establish them. Do not convert scanner banners or CVE candidates into confirmed vulnerabilities without verification.

## 3. Supervised scan-only autonomous mode

- `POST /autonomous/start` starts a human-initiated session.
- The session performs an initial Nmap TCP service-discovery scan, then may ask Gemini for bounded follow-up Nmap service-discovery scans.
- Every scan independently calls GATE (`authorize_action`) and receives a short-lived signed one-use scanner authorization.
- Follow-up ports must be in the human-approved port list and cannot repeat already-scanned ports.
- The loop is bounded to at most four scan operations total.
- `GET /autonomous/{id}` returns status, event history and results; the UI polls this endpoint.
- `POST /autonomous/{id}/stop` prevents subsequent scans.

**Current v1 boundary:** autonomous execution is Nmap TCP service discovery only. It does not perform code injection, exploitation, authentication attacks, HTTP payload tests, or other intrusive operations. Those are not yet implemented as an approval-pause-and-resume path in this version; the autonomous allowlist rejects them rather than executing them. The Stop endpoint stops future operations, but an in-flight scanner subprocess may finish before the session exits. Immediate process-level cancellation is not implemented in this patch.

## Installation

From the SENTINEL project root:

```bash
# Back up files that will be replaced.
mkdir -p .sentinel-backups/advanced-v1
cp backend/app/main.py backend/app/api/assessment.py backend/app/models/__init__.py backend/app/services/execution_signing.py frontend/src/App.tsx frontend/src/AssessmentWorkspace.tsx frontend/src/App.css .sentinel-backups/advanced-v1/

# Overlay this patch from the project root.
unzip -o sentinel-advanced-features-v1.zip -d .

# Rebuild backend (adds ReportLab) and frontend.
docker compose up -d --build backend frontend

# Inspect backend startup.
docker compose logs --tail=120 backend

# Verify API.
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/openapi.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('\\n'.join(p for p in d['paths'] if p.startswith(('/assessment/cpe','/assessment/enrich','/reports','/autonomous'))))"
```

No Docker volumes are removed or reset. `Base.metadata.create_all` creates the two new tables on startup; existing assessment records and volumes are retained.

## Validation performed for this patch

- Python source compilation passed for all backend application modules.
- ZIP structure and overlay paths were checked.
- Frontend production build was attempted but could not be completed in this environment because dependency installation was interrupted; verify with your Docker build and inspect the frontend build output.
- No live NVD, Gemini, scanner, database, or end-to-end Docker test was run here.
