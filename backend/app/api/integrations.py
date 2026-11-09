from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.tool_integration import IntegrationEnableRequest, IntegrationRegisterRequest
from app.services.tool_integrations import (
    get_integration,
    list_capabilities,
    list_integrations,
    list_versions,
    register_integration,
    set_enabled,
)

router = APIRouter(prefix="/integrations", tags=["Tool Integrations"])


@router.post("/register")
def register_tool(payload: IntegrationRegisterRequest, db: Session = Depends(get_db)):
    return register_integration(db, payload.manifest_yaml, payload.created_by)


@router.get("")
def integrations(db: Session = Depends(get_db)):
    return {"integrations": list_integrations(db)}


@router.get("/capabilities")
def integration_capabilities(db: Session = Depends(get_db)):
    return list_capabilities(db)


@router.get("/{integration_id}")
def integration(integration_id: str, db: Session = Depends(get_db)):
    return get_integration(db, integration_id)


@router.get("/{integration_id}/versions")
def integration_versions(integration_id: str, db: Session = Depends(get_db)):
    return list_versions(db, integration_id)


@router.post("/{integration_id}/enable")
def enable_integration(
    integration_id: str,
    payload: IntegrationEnableRequest,
    db: Session = Depends(get_db),
):
    return set_enabled(db, integration_id, True, payload.enabled_by)


@router.post("/{integration_id}/disable")
def disable_integration(
    integration_id: str,
    payload: IntegrationEnableRequest,
    db: Session = Depends(get_db),
):
    return set_enabled(db, integration_id, False, payload.enabled_by)
