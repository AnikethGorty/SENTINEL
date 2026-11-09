import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class ActionProposalVersion(Base):
    __tablename__ = "action_proposal_versions"
    __table_args__ = (
        UniqueConstraint("proposal_group_id", "version", name="uq_proposal_group_version"),
        Index("ix_proposal_project_status", "project_id", "status"),
        Index("ix_proposal_transcript_created", "transcript_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    proposal_group_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    transcript_id: Mapped[str] = mapped_column(String(36), ForeignKey("transcripts.id", ondelete="CASCADE"), nullable=False)
    origin: Mapped[str] = mapped_column(String(30), nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="PROPOSED", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

class ActionApproval(Base):
    __tablename__ = "action_approvals"
    __table_args__ = (
        UniqueConstraint("proposal_version_id", name="uq_approval_per_proposal_version"),
        Index("ix_action_approval_reviewer", "reviewed_by"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    proposal_version_id: Mapped[str] = mapped_column(String(36), ForeignKey("action_proposal_versions.id", ondelete="RESTRICT"), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    reviewed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
