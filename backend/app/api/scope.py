from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import ValidationError
from app.core.database import get_db
from app.models.project import Project
from app.models.scope import ScopeRevision
from app.schemas.scope import ScopeDraftRequest, ScopeValidateRequest, ScopeActivateRequest, ScopeDocument
from app.services.scope_service import create_scope_draft, validate_scope_document, validate_revision, activate_revision, project_scope_status, serialize_revision

router = APIRouter(tags=["Project Scope"])


def _project_or_404(db: Session, project_id: str):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found")


def _validation_error(exc: ValidationError):
    return [{"location": list(e["loc"]), "message": e["msg"], "type": e["type"]} for e in exc.errors()]


@router.get("/projects/{project_id}/scope")
def get_project_scope(project_id: str, db: Session = Depends(get_db)):
    _project_or_404(db, project_id)
    active = project_scope_status(db, project_id)
    latest = db.scalar(select(ScopeRevision).where(ScopeRevision.project_id == project_id).order_by(ScopeRevision.version.desc()).limit(1))
    return {"active": serialize_revision(active) if active else None, "latest": serialize_revision(latest) if latest else None}


@router.get("/projects/{project_id}/scope/versions")
def get_scope_versions(project_id: str, db: Session = Depends(get_db)):
    _project_or_404(db, project_id)
    rows = db.scalars(select(ScopeRevision).where(ScopeRevision.project_id == project_id).order_by(ScopeRevision.version.desc())).all()
    return [serialize_revision(row) for row in rows]


@router.post("/projects/{project_id}/scope/validate")
def validate_scope(project_id: str, payload: ScopeValidateRequest, db: Session = Depends(get_db)):
    _project_or_404(db, project_id)
    try:
        normalized = validate_scope_document(payload.document)
        return {"valid": True, "document": normalized, "errors": []}
    except ValidationError as exc:
        return {"valid": False, "document": None, "errors": _validation_error(exc)}


@router.post("/projects/{project_id}/scope/draft", status_code=201)
def save_scope_draft(project_id: str, payload: ScopeDraftRequest, db: Session = Depends(get_db)):
    try:
        row = create_scope_draft(db, project_id, payload.document, payload.created_by)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(422, detail={"message": "Scope document failed validation", "errors": _validation_error(exc)}) from exc
    return serialize_revision(row)


@router.post("/projects/{project_id}/scope/{revision_id}/validate")
def validate_saved_revision(project_id: str, revision_id: str, db: Session = Depends(get_db)):
    try:
        row = validate_revision(db, project_id, revision_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(422, detail={"message": "Scope document failed validation", "errors": _validation_error(exc)}) from exc
    return serialize_revision(row)


@router.post("/projects/{project_id}/scope/activate")
def activate_scope(project_id: str, payload: ScopeActivateRequest, db: Session = Depends(get_db)):
    if not payload.confirmed:
        raise HTTPException(400, "Explicit human confirmation is required")
    try:
        row = activate_revision(db, project_id, payload.revision_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return serialize_revision(row)
