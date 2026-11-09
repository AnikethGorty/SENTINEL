import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ScopeRevision(Base):
    """An immutable scope revision belonging to exactly one project."""
    __tablename__ = "scope_revisions"
    __table_args__ = (
        UniqueConstraint("project_id", "version", name="uq_scope_project_version"),
        Index("ix_scope_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT")
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False, default="human")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project = relationship("Project", backref="scope_revisions")
