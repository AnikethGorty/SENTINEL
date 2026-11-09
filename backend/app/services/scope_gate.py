from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.project import Project, Transcript, TranscriptEvent
from app.models.scope import ScopeRevision
from app.models.scan_execution import ScanExecution


# A RUNNING reservation expires if the backend dies before it can mark the job
# complete. Scanner HTTP timeout is 930 seconds; 20 minutes leaves a margin.
EXECUTION_LEASE_MINUTES = 20
RATE_WINDOW_SECONDS = 60


@dataclass(frozen=True)
class AuthorizedAction:
    project_id: str
    transcript_id: str
    scope_revision_id: str
    scope_version: int
    target: str
    tool: str
    action: str
    parameters: dict
    requested_by: str
    execution_id: str

    @property
    def operation(self) -> str:
        return f"{self.tool}.{self.action}"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _host_for_target(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Invalid URL target")
        return parsed.hostname.rstrip(".").lower()
    return candidate.rstrip(".").lower()


def _target_matches(scope_target: dict, requested_target: str) -> bool:
    kind = scope_target.get("type")
    allowed_value = str(scope_target.get("value", "")).strip()
    requested_host = _host_for_target(requested_target)

    try:
        requested_ip = ipaddress.ip_address(requested_host)
    except ValueError:
        requested_ip = None

    if kind == "ip":
        try:
            return requested_ip is not None and requested_ip == ipaddress.ip_address(allowed_value)
        except ValueError:
            return False
    if kind == "cidr":
        try:
            return requested_ip is not None and requested_ip in ipaddress.ip_network(allowed_value, strict=False)
        except ValueError:
            return False
    if kind in {"domain", "hostname"}:
        allowed_host = allowed_value.rstrip(".").lower()
        if kind == "hostname":
            return requested_host == allowed_host
        return requested_host == allowed_host or requested_host.endswith("." + allowed_host)
    if kind == "url":
        try:
            allowed = urlparse(allowed_value)
            requested = urlparse(requested_target if "://" in requested_target else "")
            allowed_path = allowed.path or "/"
            requested_path = requested.path or "/"
            return (
                requested.scheme in {"http", "https"}
                and requested.hostname is not None
                and requested.hostname.lower().rstrip(".") == (allowed.hostname or "").lower().rstrip(".")
                and (requested.port or (443 if requested.scheme == "https" else 80))
                    == (allowed.port or (443 if allowed.scheme == "https" else 80))
                and (
                    allowed_path == "/"
                    or requested_path == allowed_path
                    or requested_path.startswith(allowed_path.rstrip("/") + "/")
                )
            )
        except ValueError:
            return False
    return False


def _scope_allows_target(document: dict, target: str) -> tuple[bool, str]:
    targets = document.get("targets") or {}
    excluded = targets.get("excluded") or []
    allowed = targets.get("allowed") or []
    if any(_target_matches(item, target) for item in excluded):
        return False, "Target matches an explicitly excluded scope entry"
    if not any(_target_matches(item, target) for item in allowed):
        return False, "Target is not included in the active project scope"
    return True, "Target is in scope"


def _record_scope_event(
    db: Session, transcript_id: str, event_type: str, content: dict
) -> None:
    current = db.scalar(
        select(func.max(TranscriptEvent.sequence_number)).where(
            TranscriptEvent.transcript_id == transcript_id
        )
    ) or 0
    db.add(TranscriptEvent(
        id=str(uuid.uuid4()),
        transcript_id=transcript_id,
        sequence_number=current + 1,
        event_type=event_type,
        actor_type="system",
        actor_id="sentinel-gate",
        content=content,
    ))


def _commit_denial(
    db: Session, transcript_id: str, details: dict, reason: str, status_code: int = 403
):
    details["reason"] = reason
    details["occurred_at"] = datetime.now(timezone.utc).isoformat()
    _record_scope_event(db, transcript_id, "scope.action_denied", details)
    # Audit write must succeed before the request is rejected.
    db.commit()
    raise ScopeDenied(reason, status_code=status_code)


def authorize_action(
    db: Session,
    *,
    project_id: str,
    transcript_id: str,
    target: str,
    tool: str,
    action: str,
    parameters: dict,
    requested_by: str = "human",
) -> AuthorizedAction:
    """Authorize and reserve one scan slot atomically for this project.

    PostgreSQL row-level locking on the Project row serializes reservations and
    scope activation for the same project. Use PostgreSQL in deployment.
    """
    now = datetime.now(timezone.utc)

    # This lock is the per-project serialization point for concurrent requests.
    project = db.scalar(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    transcript = db.get(Transcript, transcript_id)
    if project is None or transcript is None or transcript.project_id != project_id:
        raise ScopeDenied("Project/transcript pair is invalid", status_code=404)

    revision = db.scalar(select(ScopeRevision).where(
        ScopeRevision.project_id == project_id,
        ScopeRevision.status == "ACTIVE",
    ).order_by(ScopeRevision.version.desc()))

    details = {
        "project_id": project_id,
        "scope_revision_id": revision.id if revision else None,
        "scope_version": revision.version if revision else None,
        "target": target,
        "tool": tool,
        "action": action,
        "parameters": parameters,
        "requested_by": requested_by,
    }

    reason = None
    document = revision.document if revision else None
    if revision is None:
        reason = "Project has no active scope revision"
    else:
        authorization = (document or {}).get("authorization") or {}
        try:
            start = _utc(datetime.fromisoformat(authorization["valid_from"].replace("Z", "+00:00")))
            end = _utc(datetime.fromisoformat(authorization["valid_until"].replace("Z", "+00:00")))
        except (KeyError, TypeError, ValueError):
            reason = "Active scope authorization dates are invalid"
        else:
            if now < start:
                reason = "Scope authorization is not yet valid"
            elif now >= end:
                reason = "Scope authorization has expired"

    operation = f"{tool}.{action}"
    if reason is None:
        operations = (document or {}).get("operations") or {}
        if operation in set(operations.get("prohibited") or []):
            reason = f"Operation {operation} is explicitly prohibited by scope"
        elif operation not in set(operations.get("allowed") or []):
            reason = f"Operation {operation} is not explicitly allowed by scope"

    if reason is None:
        try:
            matched, target_reason = _scope_allows_target(document, target)
        except (ValueError, TypeError):
            matched, target_reason = False, "Target could not be safely normalized"
        if not matched:
            reason = target_reason

    constraints = (document or {}).get("constraints") or {}
    max_rate = int(constraints.get("max_scan_rate", 5))
    max_concurrent = int(constraints.get("max_concurrent_scans", 2))

    if reason is None:
        active_count = db.scalar(
            select(func.count()).select_from(ScanExecution).where(
                ScanExecution.project_id == project_id,
                ScanExecution.status == "RUNNING",
                ScanExecution.lease_expires_at > now,
            )
        ) or 0
        if active_count >= max_concurrent:
            _commit_denial(
                db, transcript_id, details,
                f"Project concurrency limit reached ({max_concurrent} active scans)",
                status_code=429,
            )

        recent_count = db.scalar(
            select(func.count()).select_from(ScanExecution).where(
                ScanExecution.project_id == project_id,
                ScanExecution.started_at >= now - timedelta(seconds=RATE_WINDOW_SECONDS),
            )
        ) or 0
        if recent_count >= max_rate:
            _commit_denial(
                db, transcript_id, details,
                f"Project scan rate limit reached ({max_rate} scans per minute)",
                status_code=429,
            )

    if reason is not None:
        _commit_denial(db, transcript_id, details, reason)

    execution_id = str(uuid.uuid4())
    db.add(ScanExecution(
        id=execution_id,
        project_id=project_id,
        transcript_id=transcript_id,
        scope_revision_id=revision.id,
        tool=tool,
        action=action,
        target=target,
        status="RUNNING",
        started_at=now,
        lease_expires_at=now + timedelta(minutes=EXECUTION_LEASE_MINUTES),
    ))
    details.update({
        "execution_id": execution_id,
        "occurred_at": now.isoformat(),
    })
    _record_scope_event(db, transcript_id, "scope.action_authorized", details)
    # Reservation and authorization audit are committed together.
    db.commit()

    return AuthorizedAction(
        project_id=project_id,
        transcript_id=transcript_id,
        scope_revision_id=revision.id,
        scope_version=revision.version,
        target=target,
        tool=tool,
        action=action,
        parameters=parameters,
        requested_by=requested_by,
        execution_id=execution_id,
    )


def finish_execution(execution_id: str, *, status: str, error: str | None = None) -> None:
    """Mark a reserved scanner job complete/failed using a short DB session."""
    from app.core.database import SessionLocal

    if status not in {"COMPLETED", "FAILED"}:
        raise ValueError("Invalid execution terminal status")

    db = SessionLocal()
    try:
        row = db.get(ScanExecution, execution_id)
        if row is not None and row.status == "RUNNING":
            row.status = status
            row.finished_at = datetime.now(timezone.utc)
            row.error = error[:1000] if error else None
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


class ScopeDenied(Exception):
    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code
