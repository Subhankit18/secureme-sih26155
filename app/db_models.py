from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ReviewMapping(Base):
    __tablename__ = "review_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[str] = mapped_column(String(100), index=True)
    line_number: Mapped[int] = mapped_column(Integer)
    source_command: Mapped[str] = mapped_column(Text)

    ai_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ai_interpretation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)

    normalized_field: Mapped[str | None] = mapped_column(String(200), nullable=True)
    normalized_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    status: Mapped[str] = mapped_column(
        String(20), default="PENDING", index=True
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class AuditHistory(Base):
    __tablename__ = "audit_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[str] = mapped_column(String(100), index=True)
    parent_analysis_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    audit_type: Mapped[str] = mapped_column(String(50))

    compliance_percent: Mapped[float] = mapped_column(Numeric(5, 2))
    risk_score: Mapped[float] = mapped_column(Numeric(6, 2))

    total_controls: Mapped[int] = mapped_column(Integer)
    passed_controls: Mapped[int] = mapped_column(Integer)
    failed_controls: Mapped[int] = mapped_column(Integer)
    unknown_controls: Mapped[int] = mapped_column(Integer)

    approved_mapping_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


