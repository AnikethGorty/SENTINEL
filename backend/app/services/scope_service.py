from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from pydantic import ValidationError
from app.models.project import Project
from app.models.scope import ScopeRevision
from app.schemas.scope import ScopeDocument


def validate_scope_document(document: dict) -> dict:
    parsed = ScopeDocument.model_validate(document)
    return parsed.model_dump(mode="json")


def project_scope_status(db: Session, project_id: str):
    return db.scalar(select(ScopeRevision).where(
        ScopeRevision.project_id == project_id,
        ScopeRevision.status == "ACTIVE",
    ).order_by(ScopeRevision.version.desc()))


def create_scope_draft(db: Session, project_id: str, document: dict, created_by: str = "human"):
    if db.get(Project, project_id) is None:
        raise LookupError("Project not found")
    normalized = validate_scope_document(document)
    latest = db.scalar(select(ScopeRevision).where(ScopeRevision.project_id == project_id).order_by(ScopeRevision.version.desc()).limit(1))
    row = ScopeRevision(project_id=project_id, version=(latest.version + 1 if latest else 1), status="DRAFT", document=normalized, created_by=created_by)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def validate_revision(db: Session, project_id: str, revision_id: str):
    row = db.get(ScopeRevision, revision_id)
    if row is None or row.project_id != project_id:
        raise LookupError("Scope revision not found for this project")
    normalized = validate_scope_document(row.document)
    row.document = normalized
    row.validated_at = datetime.now(timezone.utc)
    row.status = "VALID"
    db.commit()
    db.refresh(row)
    return row


def activate_revision(db: Session, project_id: str, revision_id: str):
    # Serialize activation against scope-gate reservations for this project.
    project = db.scalar(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    if project is None:
        raise LookupError("Project not found")
    row = db.get(ScopeRevision, revision_id)
    if row is None or row.project_id != project_id:
        raise LookupError("Scope revision not found for this project")
    if row.status not in ("DRAFT", "VALID"):
        raise ValueError("Only a draft or validated revision can be activated")
    normalized = validate_scope_document(row.document)
    if row.validated_at is None:
        raise ValueError("Validate this revision before activation")
    now = datetime.now(timezone.utc)
    authorization = ScopeDocument.model_validate(normalized).authorization
    if authorization.valid_until <= now:
        raise ValueError("This authorization has expired")
    if authorization.valid_from > now:
        raise ValueError("This authorization is not yet valid")
    db.execute(update(ScopeRevision).where(
        ScopeRevision.project_id == project_id,
        ScopeRevision.status == "ACTIVE",
    ).values(status="SUPERSEDED"))
    row.status = "ACTIVE"
    row.activated_at = now
    db.commit()
    db.refresh(row)
    return row


def serialize_revision(row: ScopeRevision):
    return {
        "id": row.id, "project_id": row.project_id, "version": row.version,
        "status": row.status, "document": row.document, "created_by": row.created_by,
        "created_at": row.created_at, "validated_at": row.validated_at,
        "activated_at": row.activated_at,
    }
