from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .database import init_db
from .playbooks import list_incident_types
from .repository import get_case, list_cases, save_approval, save_case
from .schemas import ApprovalDecision, IncidentRequest, JobSubmitResponse
from .services.commander import finalize_case, generate_response
from .services.job_queue import get_job, submit_job as queue_submit_job
from .services.search_index import SearchIndexService

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "static"

app = FastAPI(
    title="Evidence-Gated Incident Commander Assistant - Advanced SOC/SOAR Edition",
    description=(
        "Evidence-gated SOC/SOAR assistant with deterministic playbooks, human approval gates, "
        "case persistence, async job mode, graph output, and search-ready incident records."
    ),
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "evidence-gated-incident-commander-advanced",
        "version": "3.0.0",
        "architecture": {
            "api": "FastAPI",
            "database": "SQLite default / PostgreSQL via DATABASE_URL",
            "async_jobs": "Local threaded demo queue / Celery-ready worker",
            "graph": "Inline evidence graph / Neo4j-ready connector",
            "search": "Local JSONL search / OpenSearch-ready connector",
        },
    }


@app.get("/api/incident-types")
def incident_types() -> List[Dict[str, str]]:
    return list_incident_types()


@app.post("/api/generate")
def generate(request: IncidentRequest) -> Dict[str, Any]:
    result = generate_response(request)
    case_id = save_case(request, result) if request.save_case else None
    if case_id is not None:
        result["case_id"] = case_id
    finalize_case(request, result, case_id)
    return result


@app.post("/api/jobs", response_model=JobSubmitResponse)
def submit_job(request: IncidentRequest) -> JobSubmitResponse:
    job_id = queue_submit_job(request)
    return JobSubmitResponse(job_id=job_id, status="queued", status_url=f"/api/jobs/{job_id}")


@app.get("/api/jobs/{job_id}")
def read_job(job_id: str) -> Dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Unknown job id")
    return job


@app.get("/api/cases")
def cases(limit: int = Query(25, ge=1, le=100)) -> List[Dict[str, Any]]:
    return list_cases(limit)


@app.get("/api/cases/{case_id}")
def case_detail(case_id: int) -> Dict[str, Any]:
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/api/approvals")
def approval(decision: ApprovalDecision) -> Dict[str, Any]:
    if not get_case(decision.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return save_approval(decision)


@app.get("/api/search")
def search(q: str = "", limit: int = Query(10, ge=1, le=50)) -> List[Dict[str, Any]]:
    return SearchIndexService().search(q, limit)


@app.post("/api/report/markdown")
def markdown_report(request: IncidentRequest) -> Dict[str, str]:
    result = generate_response(request)
    lines = [
        f"# Evidence-Gated Incident Commander Report: {result['incident_type']}",
        "",
        f"- Generated UTC: {result['generated_at']}",
        f"- Severity: {result['severity']}",
        f"- Environment: {result['environment']}",
        f"- Analyst: {result['analyst']}",
        f"- Playbook Confidence Score: {round(result['playbook_confidence_score'] * 100, 1)}%",
        "- Accuracy Note: This is a playbook coverage and evidence-completeness score, not a guaranteed real-world detection accuracy.",
        "",
        "## Commander Brief",
        result["case_summary"]["commander_brief"],
        "",
        "## Architecture Trace",
        *[f"- **{key.replace('_', ' ').title()}**: {value}" for key, value in result["architecture_trace"].items()],
        "",
        "## Attack Storyline",
        " -> ".join(result["attack_storyline"]),
        "",
        "## Affected Assets",
        *[f"- {a}" for a in result["affected_assets"]],
        "",
        "## Indicators",
        *[f"- {i}" for i in result["indicators"]],
        "",
        "## MITRE ATT&CK Tactics",
        *[f"- {m}" for m in result["mitre_tactics"]],
        "",
        "## Investigation Checklist",
        *[f"- [ ] {i}" for i in result["investigation_checklist"]],
        "",
        "## Evidence-Gated Actions",
    ]
    for gate in result["evidence_gated_actions"]:
        lines.extend(
            [
                f"### {gate['action']}",
                f"- Status: {gate['status']}",
                f"- Approval: {gate['approval_level']}",
                f"- Evidence Confidence: {round(gate['evidence_confidence'] * 100)}%",
                f"- Risk if wrong: {gate['risk_if_wrong']}",
                f"- Rollback: {gate['rollback']}",
                "- Verified evidence:",
                *[f"  - {e}" for e in gate.get("verified_evidence", [])],
                "- Missing evidence:",
                *[f"  - {e}" for e in gate.get("missing_evidence", [])],
                "- Required evidence:",
                *[f"  - {e}" for e in gate["required_evidence"]],
                "",
            ]
        )
    lines.extend(
        [
            "## Containment Plan",
            *[f"- [ ] {i}" for i in result["containment_plan"]],
            "",
            "## Evidence List",
            *[f"- [ ] {i}" for i in result["evidence_list"]],
            "",
            "## Escalation Summary",
            result["escalation_summary"],
        ]
    )
    return {"markdown": "\n".join(lines)}
