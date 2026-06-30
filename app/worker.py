from __future__ import annotations

import os

from celery import Celery

from .repository import save_case
from .schemas import IncidentRequest
from .services.commander import finalize_case, generate_response

broker = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
backend = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")
celery_app = Celery("incident_commander", broker=broker, backend=backend)


@celery_app.task(name="incident_commander.generate_case")
def generate_case_task(payload: dict) -> dict:
    request = IncidentRequest(**payload)
    result = generate_response(request)
    case_id = save_case(request, result) if request.save_case else None
    if case_id is not None:
        result["case_id"] = case_id
    finalize_case(request, result, case_id)
    return result
