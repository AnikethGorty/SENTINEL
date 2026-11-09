from fastapi import APIRouter, HTTPException
from app.services.scanner_client import check_scanner_health

router = APIRouter(prefix="/scanner", tags=["Scanner"])

@router.get("/health")
async def scanner_health():
    try:
        return await check_scanner_health()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Scanner agent unavailable") from exc

@router.post("/nmap")
async def direct_nmap_disabled():
    raise HTTPException(status_code=410, detail="Direct scanner execution is disabled. Create, approve, and execute an action proposal.")
