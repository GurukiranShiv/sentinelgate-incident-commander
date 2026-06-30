from __future__ import annotations

import os
import threading
import uuid
from copy import deepcopy
from typing import Any, Dict

from ..repository import save_case
from ..schemas import IncidentRequest
from .commander import finalize_case, generate_response

JOBS: Dict[str, Dict[str, Any]] = {}
LOCK = threading.Lock()


def use_celery() -> bool:
    return os.getenv("USE_CELERY", "false").lower() == "true"


def submit_job(request: IncidentRequest) -> str:
    if use_celery():
        from ..worker import generate_case_task

        task = generate_case_task.delay(request.model_dump())
        return task.id
    return submit_local_job(request)


def get_job(job_id: str) -> Dict[str, Any] | None:
    if use_celery():
        from ..worker import celery_app

        result = celery_app.AsyncResult(job_id)
        if result.state == "PENDING":
            return {"job_id": job_id, "status": "queued", "result": None, "error": None}
        if result.state in {"STARTED", "RETRY"}:
            return {"job_id": job_id, "status": "running", "result": None, "error": None}
        if result.state == "SUCCESS":
            return {"job_id": job_id, "status": "completed", "result": result.result, "error": None}
        if result.state == "FAILURE":
            return {"job_id": job_id, "status": "failed", "result": None, "error": str(result.result)}
        return {"job_id": job_id, "status": result.state.lower(), "result": None, "error": None}

    with LOCK:
        job = JOBS.get(job_id)
        return deepcopy(job) if job else None


def submit_local_job(request: IncidentRequest) -> str:
    job_id = str(uuid.uuid4())
    with LOCK:
        JOBS[job_id] = {"job_id": job_id, "status": "queued", "result": None, "error": None}
    thread = threading.Thread(target=_run_job, args=(job_id, request), daemon=True)
    thread.start()
    return job_id


def _run_job(job_id: str, request: IncidentRequest) -> None:
    with LOCK:
        JOBS[job_id]["status"] = "running"
    try:
        result = generate_response(request)
        case_id = save_case(request, result) if request.save_case else None
        if case_id is not None:
            result["case_id"] = case_id
        finalize_case(request, result, case_id)
        with LOCK:
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["result"] = result
    except Exception as exc:  # pragma: no cover
        with LOCK:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["error"] = str(exc)
