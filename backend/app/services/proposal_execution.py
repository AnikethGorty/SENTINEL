import uuid
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models.action_proposal import ActionApproval, ActionProposalVersion
from app.models.project import Project, Transcript, TranscriptEvent
from app.services.scope_gate import authorize_action, ScopeDenied, finish_execution
from app.services.scanner_client import submit_job
from app.services.execution_signing import sign_execution_authorization


def _event(db, transcript_id, event_type, content):
    seq=db.scalar(select(func.max(TranscriptEvent.sequence_number)).where(TranscriptEvent.transcript_id==transcript_id)) or 0
    db.add(TranscriptEvent(id=str(uuid.uuid4()), transcript_id=transcript_id,
        sequence_number=seq+1, event_type=event_type, actor_type="system",
        actor_id="sentinel-execution-gate", content=content))

async def execute_approved_proposal(db: Session, proposal_id: str):
    # Lock proposal and project so duplicate dispatches cannot both pass.
    proposal=db.scalar(select(ActionProposalVersion).where(ActionProposalVersion.id==proposal_id).with_for_update())
    if proposal is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    project=db.scalar(select(Project).where(Project.id==proposal.project_id).with_for_update())
    transcript=db.get(Transcript, proposal.transcript_id)
    if project is None or transcript is None or transcript.project_id != proposal.project_id:
        raise HTTPException(status_code=404, detail="Proposal project/transcript is invalid")
    approval=db.scalar(select(ActionApproval).where(ActionApproval.proposal_version_id==proposal.id))
    if proposal.status != "APPROVED" or approval is None or approval.decision != "APPROVED":
        raise HTTPException(status_code=409, detail="Only an approved proposal version can be executed")
    latest=db.scalar(select(ActionProposalVersion).where(
        ActionProposalVersion.proposal_group_id==proposal.proposal_group_id
    ).order_by(ActionProposalVersion.version.desc()).limit(1))
    if latest is None or latest.id != proposal.id:
        raise HTTPException(status_code=409, detail="Only the latest proposal version can be executed")

    proposal.status="EXECUTING"
    _event(db, proposal.transcript_id, "action.execution_started", {
        "proposal_id":proposal.id,"version":proposal.version,"approval_id":approval.id})
    db.commit()

    authorization=None
    try:
        authorization=authorize_action(db, project_id=proposal.project_id,
            transcript_id=proposal.transcript_id, target=proposal.target,
            tool=proposal.tool, action=proposal.action, parameters=proposal.parameters,
            requested_by=f"approval:{approval.reviewed_by}")
        job_id=str(uuid.uuid4())
        job={"job_id":job_id,"tool":proposal.tool,"action":proposal.action,
             "target":proposal.target,"parameters":proposal.parameters}
        token=sign_execution_authorization(job_id=job_id, proposal=proposal,
            approval=approval, scope_revision_id=authorization.scope_revision_id,
            execution_id=authorization.execution_id)
        result=await submit_job(job, authorization, token)
        proposal.status="COMPLETED"
        _event(db, proposal.transcript_id, "action.execution_completed", {
            "proposal_id":proposal.id,"version":proposal.version,
            "execution_id":authorization.execution_id,"job_id":job_id})
        db.commit()
        return {"proposal_id":proposal.id,"status":"COMPLETED",
                "execution_id":authorization.execution_id,"scanner_result":result}
    except Exception as exc:
        if authorization is not None:
            try: finish_execution(authorization.execution_id,status="FAILED",error=str(exc))
            except Exception: pass
        db.rollback()
        current=db.get(ActionProposalVersion,proposal_id)
        if current is not None:
            current.status="FAILED"
            _event(db,current.transcript_id,"action.execution_failed",{
                "proposal_id":current.id,"error":f"{type(exc).__name__}: {str(exc)[:500]}"})
            db.commit()
        if isinstance(exc, ScopeDenied):
            raise HTTPException(status_code=exc.status_code,detail=str(exc)) from exc
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=502,detail=f"Approved action execution failed: {str(exc)[:500]}") from exc
