SENTINEL assessment module repair v2

This patch restores the complete original backend/app/api/assessment.py module
and appends the Gemini Copilot/repair endpoints. The previous patch incorrectly
packaged only the appended fragment as the whole module, which removed the
original imports, router setup, and existing /assessment/run endpoint.

Import fixes:
- typing.Any
- pydantic.Field
- pydantic.ConfigDict
- retains the original module imports and existing assessment implementation.

The merged module passed Python syntax compilation.

Apply from the SENTINEL project root:
  cp backend/app/api/assessment.py backend/app/api/assessment.py.bak.$(date +%Y%m%d%H%M%S)
  unzip -o ~/Downloads/sentinel-assessment-import-fix-v2.zip -d .
  docker compose restart backend
  docker compose logs --tail=100 backend

Then verify:
  curl -i http://localhost:8000/docs
  curl -i http://localhost:8000/integrations

No database migration, volume operation, or frontend rebuild is required.
