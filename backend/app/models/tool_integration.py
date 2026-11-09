import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ToolIntegration(Base):
    __tablename__ = "tool_integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tool_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    current_version: Mapped[str] = mapped_column(String(40), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False, default="local-user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    versions: Mapped[list["ToolIntegrationVersion"]] = relationship(
        back_populates="integration", cascade="all, delete-orphan"
    )


class ToolIntegrationVersion(Base):
    __tablename__ = "tool_integration_versions"
    __table_args__ = (
        UniqueConstraint("integration_id", "version", name="uq_tool_integration_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    integration_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tool_integrations.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    manifest: Mapped[dict] = mapped_column(JSON, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    image_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(40), nullable=False, default="MANIFEST_VALID")
    runtime_validation_status: Mapped[str] = mapped_column(
        String(40), nullable=False, default="PENDING_RUNNER"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    integration: Mapped["ToolIntegration"] = relationship(back_populates="versions")
