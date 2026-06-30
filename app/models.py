from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IncidentCase(Base):
    __tablename__ = "incident_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    incident_type_id: Mapped[str] = mapped_column(String(80), index=True)
    incident_type: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(30), index=True)
    environment: Mapped[str] = mapped_column(String(80), index=True)
    analyst: Mapped[str | None] = mapped_column(String(160), nullable=True)
    confidence_score: Mapped[str] = mapped_column(String(20))
    request_json: Mapped[str] = mapped_column(Text)
    result_json: Mapped[str] = mapped_column(Text)


class ApprovalLog(Base):
    __tablename__ = "approval_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    action: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(40), index=True)
    approver: Mapped[str] = mapped_column(String(160))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
