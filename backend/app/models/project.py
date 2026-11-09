import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    authorization: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    transcripts: Mapped[list["Transcript"]] = relationship(back_populates="project", cascade="all, delete-orphan")

class Transcript(Base):
    __tablename__ = "transcripts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    project: Mapped["Project"] = relationship(back_populates="transcripts")
    events: Mapped[list["TranscriptEvent"]] = relationship(back_populates="transcript", cascade="all, delete-orphan", order_by="TranscriptEvent.sequence_number")
    executions: Mapped[list["InstructionExecution"]] = relationship(back_populates="transcript")

class TranscriptEvent(Base):
    __tablename__ = "transcript_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transcript_id: Mapped[str] = mapped_column(String(36), ForeignKey("transcripts.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence_number: Mapped[int] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(120))
    content: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    transcript: Mapped["Transcript"] = relationship(back_populates="events")
