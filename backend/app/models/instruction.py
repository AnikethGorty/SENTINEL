import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class InstructionDefinition(Base):
    __tablename__ = "instruction_definitions"
    __table_args__ = (UniqueConstraint("instruction_key", "version", name="uq_instruction_key_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    instruction_key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    trigger_event: Mapped[str | None] = mapped_column(String(100), index=True)
    trigger_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    handler_key: Mapped[str] = mapped_column(String(100), nullable=False)
    instruction_text: Mapped[str] = mapped_column(Text, nullable=False)
    input_schema: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    output_schema: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    executions: Mapped[list["InstructionExecution"]] = relationship(back_populates="instruction")

class InstructionExecution(Base):
    __tablename__ = "instruction_executions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    instruction_id: Mapped[str] = mapped_column(String(36), ForeignKey("instruction_definitions.id"), nullable=False, index=True)
    transcript_id: Mapped[str] = mapped_column(String(36), ForeignKey("transcripts.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(30), nullable=False)
    input_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    output_data: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="running")
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    instruction: Mapped["InstructionDefinition"] = relationship(back_populates="executions")
    transcript: Mapped["Transcript"] = relationship(back_populates="executions")
