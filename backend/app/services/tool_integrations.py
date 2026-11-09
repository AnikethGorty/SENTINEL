import hashlib
import json
import uuid

import yaml
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.tool_integration import ToolIntegration, ToolIntegrationVersion
from app.schemas.tool_integration import ToolManifest


def parse_and_validate_manifest(manifest_yaml: str) -> tuple[ToolManifest, dict, str]:
    try:
        raw = yaml.safe_load(manifest_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {str(exc)[:500]}") from exc

    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Manifest root must be a YAML mapping")

    try:
        manifest = ToolManifest.model_validate(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Manifest validation failed: {str(exc)[:1500]}") from exc

    normalized = manifest.model_dump(mode="json")
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return manifest, normalized, digest


def _serialize(integration: ToolIntegration, version: ToolIntegrationVersion | None) -> dict:
    return {
        "id": integration.id,
        "tool_id": integration.tool_id,
        "display_name": integration.display_name,
        "description": integration.description,
        "current_version": integration.current_version,
        "enabled": integration.enabled,
        "created_by": integration.created_by,
        "created_at": integration.created_at.isoformat() if integration.created_at else None,
        "version": {
            "id": version.id,
            "version": version.version,
            "image_reference": version.image_reference,
            "manifest_sha256": version.manifest_sha256,
            "validation_status": version.validation_status,
            "runtime_validation_status": version.runtime_validation_status,
            "manifest": version.manifest,
            "created_at": version.created_at.isoformat() if version.created_at else None,
        } if version else None,
        "execution_ready": False,
        "execution_block_reason": "Isolated container runner is not installed/configured yet",
    }


def register_integration(db: Session, manifest_yaml: str, created_by: str) -> dict:
    manifest, normalized, manifest_hash = parse_and_validate_manifest(manifest_yaml)
    integration = db.scalar(
        select(ToolIntegration).where(ToolIntegration.tool_id == manifest.tool_id).with_for_update()
    )

    if integration is None:
        integration = ToolIntegration(
            id=str(uuid.uuid4()),
            tool_id=manifest.tool_id,
            display_name=manifest.name,
            description=manifest.description,
            current_version=manifest.version,
            enabled=False,
            created_by=created_by,
        )
        db.add(integration)
        db.flush()
    else:
        existing = db.scalar(select(ToolIntegrationVersion).where(
            ToolIntegrationVersion.integration_id == integration.id,
            ToolIntegrationVersion.version == manifest.version,
        ))
        if existing:
            raise HTTPException(status_code=409, detail="This integration version is already registered")
        integration.display_name = manifest.name
        integration.description = manifest.description
        integration.current_version = manifest.version
        # New versions are not silently enabled.
        integration.enabled = False

    version = ToolIntegrationVersion(
        id=str(uuid.uuid4()),
        integration_id=integration.id,
        version=manifest.version,
        manifest=normalized,
        manifest_sha256=manifest_hash,
        image_reference=manifest.runtime.image,
        validation_status="MANIFEST_VALID",
        runtime_validation_status="PENDING_RUNNER",
    )
    db.add(version)
    db.commit()
    db.refresh(integration)
    db.refresh(version)
    return _serialize(integration, version)


def _current_version(db: Session, integration: ToolIntegration):
    return db.scalar(select(ToolIntegrationVersion).where(
        ToolIntegrationVersion.integration_id == integration.id,
        ToolIntegrationVersion.version == integration.current_version,
    ))


def list_integrations(db: Session) -> list[dict]:
    rows = db.scalars(select(ToolIntegration).order_by(ToolIntegration.created_at.desc())).all()
    return [_serialize(row, _current_version(db, row)) for row in rows]


def get_integration(db: Session, integration_id: str) -> dict:
    row = db.get(ToolIntegration, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return _serialize(row, _current_version(db, row))


def list_versions(db: Session, integration_id: str) -> dict:
    row = db.get(ToolIntegration, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    versions = db.scalars(select(ToolIntegrationVersion).where(
        ToolIntegrationVersion.integration_id == integration_id
    ).order_by(ToolIntegrationVersion.created_at.desc())).all()
    return {"integration_id": integration_id, "versions": [
        {
            "id": item.id,
            "version": item.version,
            "image_reference": item.image_reference,
            "manifest_sha256": item.manifest_sha256,
            "validation_status": item.validation_status,
            "runtime_validation_status": item.runtime_validation_status,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in versions
    ]}


def set_enabled(db: Session, integration_id: str, enabled: bool, actor: str) -> dict:
    row = db.get(ToolIntegration, integration_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if enabled:
        raise HTTPException(
            status_code=409,
            detail="Cannot enable execution until the isolated container runner and runtime validation are configured",
        )
    row.enabled = False
    db.commit()
    db.refresh(row)
    return _serialize(row, _current_version(db, row))


def list_capabilities(db: Session) -> dict:
    rows = db.scalars(select(ToolIntegration).where(
        ToolIntegration.enabled.is_(True)
    ).order_by(ToolIntegration.tool_id)).all()
    capabilities = []
    for integration in rows:
        version = _current_version(db, integration)
        if not version:
            continue
        manifest = version.manifest
        for operation, definition in manifest.get("operations", {}).items():
            capabilities.append({
                "tool": integration.tool_id,
                "action": operation,
                "description": definition.get("description", ""),
                "source": "user_supplied",
                "integration_id": integration.id,
                "integration_version": version.version,
                "manifest_sha256": version.manifest_sha256,
                "capabilities": manifest.get("capabilities", []),
                "parameters": definition.get("parameters", {}),
                "executable": False,
                "execution_block_reason": "Isolated container runner is not installed/configured yet",
            })
    return {"capabilities": capabilities, "execution_ready": False}
