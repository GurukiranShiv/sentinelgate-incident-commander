from __future__ import annotations

import json
from typing import Any, Dict, List

from sqlalchemy import desc, select

from .database import session_scope
from .models import ApprovalLog, IncidentCase
from .schemas import ApprovalDecision, IncidentRequest


def save_case(request: IncidentRequest, result: Dict[str, Any]) -> int:
    with session_scope() as db:
        case = IncidentCase(
            incident_type_id=result["incident_type_id"],
            incident_type=result["incident_type"],
            severity=result["severity"],
            environment=result["environment"],
            analyst=request.analyst,
            confidence_score=str(result["playbook_confidence_score"]),
            request_json=request.model_dump_json(),
            result_json=json.dumps(result),
        )
        db.add(case)
        db.flush()
        case_id = case.id
    return case_id


def list_cases(limit: int = 25) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 100))
    with session_scope() as db:
        rows = db.execute(select(IncidentCase).order_by(desc(IncidentCase.created_at)).limit(limit)).scalars().all()
        return [
            {
                "id": row.id,
                "created_at": row.created_at.isoformat(),
                "incident_type_id": row.incident_type_id,
                "incident_type": row.incident_type,
                "severity": row.severity,
                "environment": row.environment,
                "analyst": row.analyst,
                "confidence_score": float(row.confidence_score),
            }
            for row in rows
        ]


def get_case(case_id: int) -> Dict[str, Any] | None:
    with session_scope() as db:
        row = db.get(IncidentCase, case_id)
        if not row:
            return None
        result = json.loads(row.result_json)
        result["case_id"] = row.id
        result["stored_at"] = row.created_at.isoformat()
        return result


def save_approval(decision: ApprovalDecision) -> Dict[str, Any]:
    with session_scope() as db:
        log = ApprovalLog(
            case_id=decision.case_id,
            action=decision.action,
            decision=decision.decision,
            approver=decision.approver,
            reason=decision.reason,
        )
        db.add(log)
        db.flush()
        return {
            "id": log.id,
            "case_id": log.case_id,
            "created_at": log.created_at.isoformat(),
            "action": log.action,
            "decision": log.decision,
            "approver": log.approver,
            "reason": log.reason,
        }
