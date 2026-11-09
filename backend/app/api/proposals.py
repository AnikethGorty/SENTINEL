from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.action_proposal import ProposalCreate, ProposalDecision, ProposalRevision
from app.services.action_proposals import create_proposal, decide_proposal, get_proposal, list_proposals, revise_proposal
from app.services.proposal_execution import execute_approved_proposal

router = APIRouter(tags=["Action Proposals"])

@router.post("/projects/{project_id}/transcripts/{transcript_id}/proposals")
def create_action_proposal(project_id: str, transcript_id: str, payload: ProposalCreate, db: Session = Depends(get_db)):
    return create_proposal(db, project_id, transcript_id, payload)

@router.get("/projects/{project_id}/proposals")
def get_project_proposals(project_id: str, transcript_id: str | None = None, db: Session = Depends(get_db)):
    return {"proposals": list_proposals(db, project_id, transcript_id)}

@router.get("/proposals/{proposal_id}")
def get_action_proposal(proposal_id: str, db: Session = Depends(get_db)):
    return get_proposal(db, proposal_id)

@router.post("/proposals/{proposal_id}/revise")
def revise_action_proposal(proposal_id: str, payload: ProposalRevision, db: Session = Depends(get_db)):
    return revise_proposal(db, proposal_id, payload)

@router.post("/proposals/{proposal_id}/decision")
def decide_action_proposal(proposal_id: str, payload: ProposalDecision, db: Session = Depends(get_db)):
    return decide_proposal(db, proposal_id, payload)

@router.post("/proposals/{proposal_id}/execute")
async def execute_action_proposal(proposal_id: str, db: Session = Depends(get_db)):
    return await execute_approved_proposal(db, proposal_id)
