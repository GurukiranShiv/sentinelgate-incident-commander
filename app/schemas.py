from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class IncidentRequest(BaseModel):
    incident_type: str = Field(..., description="Incident type id from /api/incident-types")
    severity: str = Field("medium", pattern="^(low|medium|high|critical)$")
    environment: str = Field("enterprise", description="enterprise, cloud, endpoint, web, hybrid, etc.")
    affected_assets: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    analyst: Optional[str] = Field(None, description="Optional analyst name or team handling the case")
    save_case: bool = Field(True, description="Persist the generated commander report")


class JobSubmitResponse(BaseModel):
    job_id: str
    status: str
    status_url: str


class ApprovalDecision(BaseModel):
    case_id: int
    action: str
    decision: str = Field(..., pattern="^(approved|rejected|needs_more_evidence)$")
    approver: str = "SOC Analyst"
    reason: Optional[str] = None
