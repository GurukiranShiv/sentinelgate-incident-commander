from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import HTTPException

from ..decision_engine import (
    DEFAULT_ASSURANCE_CHECKS,
    SEVERITY_ESCALATION,
    build_approval_matrix,
    build_attack_storyline,
    build_evidence_gates,
    prioritized_actions,
    quality_score,
    timeline_template,
)
from ..playbooks import PLAYBOOKS
from ..schemas import IncidentRequest
from .evidence_graph import EvidenceGraphService
from .search_index import SearchIndexService


def generate_response(request: IncidentRequest) -> Dict[str, Any]:
    if request.incident_type not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail="Unknown incident type")

    pb = PLAYBOOKS[request.incident_type]
    assets = request.affected_assets or ["Not specified"]
    indicators = request.indicators or []
    evidence_gates = build_evidence_gates(request.incident_type, indicators, request.notes)
    score = quality_score(pb, request.severity, indicators, request.affected_assets, request.notes, evidence_gates)
    graph_service = EvidenceGraphService()

    result: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_type_id": request.incident_type,
        "incident_type": pb["title"],
        "severity": request.severity.upper(),
        "environment": request.environment,
        "analyst": request.analyst or "Not assigned",
        "affected_assets": assets,
        "indicators": indicators or ["Not specified"],
        "playbook_confidence_score": score,
        "quality_note": "This is a playbook coverage, evidence-completeness, and consistency score. It is not a guaranteed real-world detection accuracy percentage.",
        "mitre_tactics": pb["mitre"],
        "attack_storyline": build_attack_storyline(request.incident_type),
        "investigation_checklist": pb["investigation_checklist"],
        "containment_plan": pb["containment_plan"],
        "evidence_list": pb["evidence_list"],
        "evidence_gated_actions": evidence_gates,
        "approval_matrix": build_approval_matrix(evidence_gates),
        "assurance_checks": DEFAULT_ASSURANCE_CHECKS,
        "escalation_summary": f"{pb['escalation_summary']} Severity overlay: {SEVERITY_ESCALATION[request.severity]}",
        "priority_actions": prioritized_actions(pb, request.severity, evidence_gates),
        "soar_timeline": timeline_template(),
        "architecture_trace": {
            "api_layer": "FastAPI validates request and generates OpenAPI docs",
            "decision_engine": "Evidence-gated deterministic playbook logic",
            "case_store": "SQLite locally or PostgreSQL in Docker mode",
            "queue_layer": "In-memory async demo jobs locally; Redis/Celery ready in advanced mode",
            "graph_layer": "Local graph response and optional Neo4j persistence",
            "search_layer": "Local JSONL index and optional OpenSearch persistence",
            "human_in_loop": "Approval gates separate automation-safe actions from risky containment",
        },
        "case_summary": {
            "commander_brief": f"{pb['title']} detected in {request.environment} environment with {request.severity.upper()} severity. Validate scope, run evidence gates, preserve evidence, execute approved containment, and escalate according to impact.",
            "analyst_focus": "Separate attempted activity from confirmed compromise, preserve original telemetry, and document every decision with timestamp, owner, evidence, approval, and rollback path.",
            "notes": request.notes or "No analyst notes provided.",
        },
    }
    result["evidence_graph"] = graph_service.build_graph(result)
    return result


def finalize_case(request: IncidentRequest, result: Dict[str, Any], case_id: int | None) -> None:
    # Persist optional external architecture data. These calls are failure-tolerant.
    GraphService = EvidenceGraphService()
    GraphService.persist(result)
    SearchIndexService().index_case(case_id, result)
