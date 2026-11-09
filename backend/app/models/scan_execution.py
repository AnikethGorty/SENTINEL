import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ScanExecution(Base):
    """Database-backed reservation and lifecycle record for a scanner job."""
    __tablename__ = "scan_executions"
    __table_args__ = (
        Index("ix_scan_project_status", "project_id", "status"),
        Index("ix_scan_project_started", "project_id", "started_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    transcript_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("transcripts.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    scope_revision_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scope_revisions.id"),
        nullable=False, index=True,
    )
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="RUNNING")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    lease_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(String(1000))
