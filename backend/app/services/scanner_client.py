import os
import httpx
from app.services.scope_gate import AuthorizedAction, finish_execution

SCANNER_URL=os.getenv("SCANNER_URL","http://scanner:8100")
SCANNER_API_KEY=os.getenv("SCANNER_API_KEY","")

async def submit_job(job: dict, authorization: AuthorizedAction, execution_token: str) -> dict:
    if not isinstance(authorization,AuthorizedAction):
        raise PermissionError("Scope-gate authorization is required")
    expected=(authorization.tool,authorization.action,authorization.target,authorization.parameters)
    actual=(job.get("tool"),job.get("action"),job.get("target"),job.get("parameters",{}))
    if actual != expected:
        finish_execution(authorization.execution_id,status="FAILED",error="Job did not match authorization")
        raise PermissionError("Scanner job does not match scope-gate authorization")
    if not execution_token:
        raise PermissionError("Cryptographic execution authorization is required")
    headers={"X-Scanner-Key":SCANNER_API_KEY,"X-Execution-Authorization":execution_token}
    try:
        async with httpx.AsyncClient(timeout=930) as client:
            response=await client.post(f"{SCANNER_URL}/jobs",json=job,headers=headers)
            if response.status_code>=400:
                raise RuntimeError(f"Scanner returned HTTP {response.status_code}: {response.text[:2000]}")
            result=response.json()
        finish_execution(authorization.execution_id,status="COMPLETED")
        return result
    except Exception as exc:
        try: finish_execution(authorization.execution_id,status="FAILED",error=f"{type(exc).__name__}: {exc}")
        except Exception: pass
        raise

async def check_scanner_health():
    async with httpx.AsyncClient(timeout=5) as client:
        response=await client.get(f"{SCANNER_URL}/health")
        response.raise_for_status()
        return response.json()
