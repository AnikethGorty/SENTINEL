import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class ReportDraft(Base):
    __tablename__ = "report_drafts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    transcript_id: Mapped[str] = mapped_column(String(36), ForeignKey("transcripts.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="DRAFT")
    components: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    approved_by: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

class AutonomousSession(Base):
    __tablename__ = "autonomous_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    transcript_id: Mapped[str] = mapped_column(String(36), ForeignKey("transcripts.id", ondelete="CASCADE"), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="STARTING")
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    results: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    stop_requested: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
