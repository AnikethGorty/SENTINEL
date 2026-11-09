import uuid
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models.action_proposal import ActionApproval, ActionProposalVersion
from app.models.project import Project, Transcript, TranscriptEvent

def _lock_project_and_check_transcript(db: Session, project_id: str, transcript_id: str):
    project = db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    transcript = db.get(Transcript, transcript_id)
    if project is None or transcript is None or transcript.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project/transcript pair not found")

def _append_event(db: Session, transcript_id: str, event_type: str, actor_type: str, actor_id: str, content: dict):
    current = db.scalar(select(func.max(TranscriptEvent.sequence_number)).where(TranscriptEvent.transcript_id == transcript_id)) or 0
    db.add(TranscriptEvent(
        id=str(uuid.uuid4()), transcript_id=transcript_id, sequence_number=current + 1,
        event_type=event_type, actor_type=actor_type, actor_id=actor_id, content=content,
    ))

def _serialize(row: ActionProposalVersion, approval: ActionApproval | None = None) -> dict:
    return {
        "id": row.id, "proposal_group_id": row.proposal_group_id, "version": row.version,
        "project_id": row.project_id, "transcript_id": row.transcript_id,
        "origin": row.origin, "created_by": row.created_by, "tool": row.tool,
        "action": row.action, "target": row.target, "parameters": row.parameters,
        "reason": row.reason, "priority": row.priority, "status": row.status,
        "created_at": row.created_at.isoformat(),
        "approval": None if approval is None else {
            "id": approval.id, "decision": approval.decision,
            "reviewed_by": approval.reviewed_by, "comment": approval.comment,
            "created_at": approval.created_at.isoformat(),
        },
    }

def create_proposal(db: Session, project_id: str, transcript_id: str, payload) -> dict:
    _lock_project_and_check_transcript(db, project_id, transcript_id)
    row = ActionProposalVersion(
        id=str(uuid.uuid4()), proposal_group_id=str(uuid.uuid4()), version=1,
        project_id=project_id, transcript_id=transcript_id, origin=payload.origin,
        created_by=payload.created_by, tool=payload.tool, action=payload.action,
        target=payload.target, parameters=payload.parameters, reason=payload.reason,
        priority=payload.priority, status="PROPOSED",
    )
    db.add(row)
    _append_event(db, transcript_id, "action.proposed", payload.origin.lower(), payload.created_by, {
        "proposal_id": row.id, "proposal_group_id": row.proposal_group_id, "version": 1,
        "tool": row.tool, "action": row.action, "target": row.target,
        "parameters": row.parameters, "reason": row.reason, "priority": row.priority,
    })
    db.commit()
    db.refresh(row)
    return _serialize(row)

def list_proposals(db: Session, project_id: str, transcript_id: str | None = None) -> list[dict]:
    query = select(ActionProposalVersion).where(ActionProposalVersion.project_id == project_id)
    if transcript_id:
        query = query.where(ActionProposalVersion.transcript_id == transcript_id)
    rows = db.scalars(query.order_by(ActionProposalVersion.created_at.desc())).all()
    return [_serialize(row, db.scalar(select(ActionApproval).where(ActionApproval.proposal_version_id == row.id))) for row in rows]

def revise_proposal(db: Session, proposal_id: str, payload) -> dict:
    current = db.scalar(select(ActionProposalVersion).where(ActionProposalVersion.id == proposal_id).with_for_update())
    if current is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    _lock_project_and_check_transcript(db, current.project_id, current.transcript_id)
    latest = db.scalar(
        select(ActionProposalVersion).where(ActionProposalVersion.proposal_group_id == current.proposal_group_id)
        .order_by(ActionProposalVersion.version.desc()).limit(1)
    )
    if latest is None or latest.id != current.id:
        raise HTTPException(status_code=409, detail="Only the latest proposal version can be revised")
    if current.status in {"EXECUTING", "COMPLETED"}:
        raise HTTPException(status_code=409, detail="An executing or completed proposal cannot be revised")
    previous_status = current.status
    current.status = "SUPERSEDED"
    row = ActionProposalVersion(
        id=str(uuid.uuid4()), proposal_group_id=current.proposal_group_id, version=current.version + 1,
        project_id=current.project_id, transcript_id=current.transcript_id, origin=current.origin,
        created_by=payload.edited_by, tool=payload.tool, action=payload.action, target=payload.target,
        parameters=payload.parameters, reason=payload.reason, priority=payload.priority, status="PROPOSED",
    )
    db.add(row)
    _append_event(db, current.transcript_id, "action.revised", "human", payload.edited_by, {
        "previous_proposal_id": current.id, "proposal_id": row.id,
        "proposal_group_id": row.proposal_group_id, "version": row.version,
        "previous_status": previous_status, "tool": row.tool, "action": row.action,
        "target": row.target, "parameters": row.parameters,
    })
    db.commit()
    db.refresh(row)
    return _serialize(row)

def decide_proposal(db: Session, proposal_id: str, payload) -> dict:
    row = db.scalar(select(ActionProposalVersion).where(ActionProposalVersion.id == proposal_id).with_for_update())
    if row is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    _lock_project_and_check_transcript(db, row.project_id, row.transcript_id)
    if row.status != "PROPOSED":
        raise HTTPException(status_code=409, detail=f"Proposal is not pending review (status={row.status})")
    approval = ActionApproval(
        id=str(uuid.uuid4()), proposal_version_id=row.id, decision=payload.decision,
        reviewed_by=payload.reviewed_by, comment=payload.comment,
    )
    row.status = payload.decision
    db.add(approval)
    _append_event(db, row.transcript_id, f"action.{payload.decision.lower()}", "human", payload.reviewed_by, {
        "proposal_id": row.id, "proposal_group_id": row.proposal_group_id,
        "version": row.version, "approval_id": approval.id,
        "decision": payload.decision, "comment": payload.comment,
    })
    db.commit()
    db.refresh(row)
    db.refresh(approval)
    return _serialize(row, approval)

def get_proposal(db: Session, proposal_id: str) -> dict:
    row = db.get(ActionProposalVersion, proposal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    approval = db.scalar(select(ActionApproval).where(ActionApproval.proposal_version_id == row.id))
    return _serialize(row, approval)
