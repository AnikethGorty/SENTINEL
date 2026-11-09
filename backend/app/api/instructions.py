from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Project, Transcript, TranscriptEvent
from app.schemas.instruction import ProjectCreate, TranscriptCreate, InstructionExecuteRequest, InstructionLoadRequest
from app.services.instruction_library import HANDLERS, execute_instruction, get_instruction, list_instructions, load_for_trigger, load_instruction

router = APIRouter(tags=["Projects & Instruction Library"])

@router.post("/projects", status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    row = Project(name=payload.name, description=payload.description, authorization=payload.authorization)
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "name": row.name, "description": row.description, "authorization": row.authorization, "created_at": row.created_at}

@router.get("/projects")
def get_projects(db: Session = Depends(get_db)):
    rows = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [{"id": r.id, "name": r.name, "description": r.description, "created_at": r.created_at} for r in rows]

@router.post("/projects/{project_id}/transcripts", status_code=201)
def create_transcript(project_id: str, payload: TranscriptCreate, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found")
    row = Transcript(project_id=project_id, name=payload.name)
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "project_id": row.project_id, "name": row.name, "status": row.status, "created_at": row.created_at}

@router.get("/projects/{project_id}/transcripts")
def get_transcripts(project_id: str, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found")
    rows = db.scalars(select(Transcript).where(Transcript.project_id == project_id).order_by(Transcript.created_at.desc())).all()
    return [{"id": r.id, "project_id": r.project_id, "name": r.name, "status": r.status} for r in rows]

@router.get("/transcripts/{transcript_id}/events")
def get_transcript_events(transcript_id: str, db: Session = Depends(get_db)):
    if db.get(Transcript, transcript_id) is None:
        raise HTTPException(404, "Transcript not found")
    rows = db.scalars(select(TranscriptEvent).where(TranscriptEvent.transcript_id == transcript_id).order_by(TranscriptEvent.sequence_number)).all()
    return [{"id": r.id, "sequence_number": r.sequence_number, "event_type": r.event_type, "actor_type": r.actor_type, "actor_id": r.actor_id, "content": r.content, "created_at": r.created_at} for r in rows]

@router.get("/instructions")
def get_instructions(db: Session = Depends(get_db)):
    return [{
        "id": i.id, "instruction_key": i.instruction_key, "version": i.version,
        "name": i.name, "description": i.description, "category": i.category,
        "trigger_event": i.trigger_event, "trigger_mode": i.trigger_mode,
        "enabled": i.enabled, "executable": i.handler_key in HANDLERS,
    } for i in list_instructions(db)]

@router.get("/instructions/{instruction_id}")
def inspect_instruction(instruction_id: str, db: Session = Depends(get_db)):
    i = get_instruction(db, instruction_id)
    if i is None: raise HTTPException(404, "Instruction not found")
    return {
        "id": i.id, "instruction_key": i.instruction_key, "version": i.version,
        "name": i.name, "description": i.description, "category": i.category,
        "trigger_event": i.trigger_event, "trigger_mode": i.trigger_mode,
        "handler_key": i.handler_key, "handler_registered": i.handler_key in HANDLERS,
        "instruction_text": i.instruction_text, "input_schema": i.input_schema,
        "output_schema": i.output_schema, "enabled": i.enabled,
    }

@router.post("/instructions/{instruction_id}/load")
def load_one_instruction(instruction_id: str, payload: InstructionLoadRequest, db: Session = Depends(get_db)):
    i = get_instruction(db, instruction_id)
    if i is None: raise HTTPException(404, "Instruction not found")
    try: return load_instruction(db, i, payload.transcript_id, payload.requested_by)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc

@router.post("/instructions/trigger/{trigger_event}/load")
def load_triggered_instructions(trigger_event: str, transcript_id: str, db: Session = Depends(get_db)):
    try: return load_for_trigger(db, trigger_event, transcript_id)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc

@router.post("/instructions/{instruction_id}/execute")
def run_instruction(instruction_id: str, payload: InstructionExecuteRequest, db: Session = Depends(get_db)):
    i = get_instruction(db, instruction_id)
    if i is None: raise HTTPException(404, "Instruction not found")
    try:
        row = execute_instruction(db, i, payload.transcript_id, payload.requested_by, payload.input_data)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "execution_id": row.id, "instruction_id": row.instruction_id,
        "transcript_id": row.transcript_id, "status": row.status,
        "output": row.output_data, "error": row.error,
        "started_at": row.started_at, "finished_at": row.finished_at,
    }
