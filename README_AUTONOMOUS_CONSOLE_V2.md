# SENTINEL Autonomous Console UI & Event Log Update

This is a small overlay patch for installations that already have `sentinel-advanced-features-v1.zip` applied.

## Changes

1. Moved the autonomous scanner controls into **Assessment Operations**, directly below the Gemini investigation copilot.
2. Removed the autonomous-mode tab from the separate **Intelligence & Delivery** screen. That screen remains for optional CPE/CVE enrichment and report creation/review.
3. Added a live system event log to Assessment Operations. It polls the session every 1.2 seconds and displays each event with timestamp, event type, message, and expandable structured details.
4. Added explicit backend events for:
   - session started
   - GATE authorization and GATE rejection
   - scanner dispatch and scanner response
   - scanner stdout/stderr capture
   - Nmap XML parsing success/failure
   - Nmap details sent to Gemini
   - Gemini provider/model selected
   - Gemini response received
   - Gemini model/planner failure
   - Gemini action review and rejection
   - follow-up scan completion
   - session stop and final state
5. Keeps the event log visible after a session completes or fails. A new session can be started from the completed session view.

## Install

From the SENTINEL project root:

```bash
mkdir -p .sentinel-backups/autonomous-console-v2
cp backend/app/api/advanced.py \
   frontend/src/AssessmentWorkspace.tsx \
   frontend/src/AdvancedFeatures.tsx \
   frontend/src/App.css \
   .sentinel-backups/autonomous-console-v2/

unzip -o ~/Downloads/sentinel-autonomous-console-v2.zip -d .

docker compose up -d --build backend frontend
docker compose logs --tail=120 backend
```

No database schema changes, migrations, volume deletion, or Docker socket access are required.

## Notes

- The autonomous scanner remains scan-only Nmap TCP service discovery. No injection, exploit, authentication attack, or state-changing operation is enabled.
- Each Nmap operation still goes through GATE and the existing one-use signed scanner authorization.
- Stop prevents later scans. A currently running scanner subprocess may finish before the session exits.
- Scanner stdout/stderr is stored in expandable log details (bounded to 20,000/10,000 characters per output event); Gemini response previews are bounded to 2,500 characters per event.
- The UI keeps the event log visible after completion. It does not yet provide a cross-session history picker; the current session remains visible while this Assessment Operations page stays mounted.
- Backend Python compilation passed. Frontend production build was not run in this environment; verify the Docker frontend build.
