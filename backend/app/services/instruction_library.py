from datetime import datetime, timezone
from typing import Any, Callable
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models import InstructionDefinition, InstructionExecution, Transcript, TranscriptEvent
from app.services.vulnerability_intel import enrich_services

Handler = Callable[[dict[str, Any]], dict[str, Any]]

def service_to_cve_correlation(payload: dict[str, Any]) -> dict[str, Any]:
    services = payload.get("services")
    if not isinstance(services, list):
        raise ValueError("'services' must be a list")
    enriched = enrich_services(services)
    return {
        "services": enriched,
        "summary": {
            "services_processed": len(enriched),
            "cve_candidates": sum(len(s.get("cve_candidates", [])) for s in enriched),
            "engine": "sentinel-deterministic-vulnerability-intelligence",
        },
    }

# Database records select a handler by key; they cannot introduce executable Python.
HANDLERS: dict[str, Handler] = {"service_to_cve_correlation": service_to_cve_correlation}

BUILTIN_INSTRUCTIONS = [{
    "instruction_key": "service_to_cve_correlation",
    "version": 1,
    "name": "Service-to-CVE Correlation",
    "description": "Evaluate discovered services against curated CVE applicability profiles. Candidates are not confirmation of exploitability.",
    "category": "vulnerability_intelligence",
    "trigger_event": "service_discovery.completed",
    "trigger_mode": "automatic",
    "handler_key": "service_to_cve_correlation",
    "instruction_text": "Evaluate product identity, version and known prerequisites against curated CVE profiles. Preserve uncertainty and missing evidence. Never describe a candidate as confirmed exploitable.",
    "input_schema": {"type": "object", "required": ["services"], "properties": {"services": {"type": "array", "items": {"type": "object"}}}},
    "output_schema": {"type": "object", "required": ["services", "summary"]},
}]

def seed_builtin_instructions(db: Session) -> None:
    for item in BUILTIN_INSTRUCTIONS:
        exists = db.scalar(select(InstructionDefinition).where(
            InstructionDefinition.instruction_key == item["instruction_key"],
            InstructionDefinition.version == item["version"],
        ))
        if exists is None:
            db.add(InstructionDefinition(**item))
    db.commit()

def list_instructions(db: Session):
    return list(db.scalars(select(InstructionDefinition).where(
        InstructionDefinition.enabled.is_(True)
    ).order_by(InstructionDefinition.instruction_key, InstructionDefinition.version.desc())).all())

def get_instruction(db: Session, instruction_id: str):
    return db.get(InstructionDefinition, instruction_id)

def _next_sequence(db: Session, transcript_id: str) -> int:
    current = db.scalar(select(func.coalesce(func.max(TranscriptEvent.sequence_number), 0)).where(
        TranscriptEvent.transcript_id == transcript_id
    )) or 0
    return current + 1

def load_instruction(db: Session, instruction: InstructionDefinition, transcript_id: str, requested_by: str):
    if db.get(Transcript, transcript_id) is None:
        raise ValueError("Transcript not found")
    if not instruction.enabled:
        raise ValueError("Instruction is disabled")
    db.add(TranscriptEvent(
        transcript_id=transcript_id,
        sequence_number=_next_sequence(db, transcript_id),
        event_type="instruction_loaded",
        actor_type=requested_by,
        content={
            "instruction_id": instruction.id,
            "instruction_key": instruction.instruction_key,
            "version": instruction.version,
            "name": instruction.name,
            "instruction_text": instruction.instruction_text,
            "handler_key": instruction.handler_key,
        },
    ))
    db.commit()
    return {
        "instruction_id": instruction.id,
        "instruction_key": instruction.instruction_key,
        "version": instruction.version,
        "name": instruction.name,
        "description": instruction.description,
        "instruction_text": instruction.instruction_text,
        "input_schema": instruction.input_schema,
        "output_schema": instruction.output_schema,
        "handler_available": instruction.handler_key in HANDLERS,
    }

def load_for_trigger(db: Session, trigger_event: str, transcript_id: str):
    matches = db.scalars(select(InstructionDefinition).where(
        InstructionDefinition.enabled.is_(True),
        InstructionDefinition.trigger_mode == "automatic",
        InstructionDefinition.trigger_event == trigger_event,
    )).all()
    return [load_instruction(db, item, transcript_id, "system") for item in matches]

def execute_instruction(db: Session, instruction: InstructionDefinition, transcript_id: str, requested_by: str, input_data: dict):
    if db.get(Transcript, transcript_id) is None:
        raise ValueError("Transcript not found")
    if not instruction.enabled:
        raise ValueError("Instruction is disabled")
    handler = HANDLERS.get(instruction.handler_key)
    if handler is None:
        raise ValueError("No trusted executable handler is registered for this instruction")

    execution = InstructionExecution(
        instruction_id=instruction.id,
        transcript_id=transcript_id,
        requested_by=requested_by,
        input_data=input_data,
        status="running",
    )
    db.add(execution)
    db.flush()
    try:
        execution.output_data = handler(input_data)
        execution.status = "completed"
    except Exception as exc:
        execution.status = "failed"
        execution.error = f"{type(exc).__name__}: {str(exc)[:1000]}"
    execution.finished_at = datetime.now(timezone.utc)

    db.add(TranscriptEvent(
        transcript_id=transcript_id,
        sequence_number=_next_sequence(db, transcript_id),
        event_type="instruction_execution",
        actor_type=requested_by,
        content={
            "execution_id": execution.id,
            "instruction_id": instruction.id,
            "instruction_key": instruction.instruction_key,
            "version": instruction.version,
            "status": execution.status,
            "output": execution.output_data,
            "error": execution.error,
        },
    ))
    db.commit()
    db.refresh(execution)
    return execution
