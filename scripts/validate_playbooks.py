from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.decision_engine import INCIDENT_PROFILES
from app.playbooks import PLAYBOOKS
from app.schemas import IncidentRequest
from app.services.commander import generate_response

REQUIRED_PLAYBOOK_KEYS = {
    "title",
    "description",
    "base_confidence",
    "mitre",
    "investigation_checklist",
    "containment_plan",
    "evidence_list",
    "escalation_summary",
}

REQUIRED_RESPONSE_KEYS = {
    "architecture_trace",
    "evidence_graph",
    "evidence_gated_actions",
    "approval_matrix",
    "attack_storyline",
    "soar_timeline",
}


def main() -> None:
    errors: list[str] = []

    for key, playbook in PLAYBOOKS.items():
        missing = REQUIRED_PLAYBOOK_KEYS - set(playbook)
        if missing:
            errors.append(f"{key} missing playbook keys: {sorted(missing)}")
        if len(playbook.get("investigation_checklist", [])) < 6:
            errors.append(f"{key} needs at least 6 investigation steps")
        if len(playbook.get("containment_plan", [])) < 4:
            errors.append(f"{key} needs at least 4 containment steps")
        if len(playbook.get("evidence_list", [])) < 5:
            errors.append(f"{key} needs at least 5 evidence items")
        if key not in INCIDENT_PROFILES:
            errors.append(f"{key} missing evidence-gated decision profile")
        else:
            profile = INCIDENT_PROFILES[key]
            if len(profile.get("storyline", [])) < 4:
                errors.append(f"{key} needs at least 4 storyline stages")
            if len(profile.get("evidence_gates", [])) < 3:
                errors.append(f"{key} needs at least 3 evidence gates")

        demo = generate_response(
            IncidentRequest(
                incident_type=key,
                severity="high",
                environment="validation lab",
                affected_assets=["asset-validation"],
                indicators=["validation indicator"],
                notes="Validation pass for evidence-gated response completeness.",
                save_case=False,
            )
        )
        missing_response = REQUIRED_RESPONSE_KEYS - set(demo)
        if missing_response:
            errors.append(f"{key} response missing advanced keys: {sorted(missing_response)}")
        if len(demo.get("evidence_graph", {}).get("nodes", [])) < 6:
            errors.append(f"{key} graph output is too small")

    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)

    print(
        f"Validation passed: {len(PLAYBOOKS)} playbooks include evidence gates, architecture trace, graph output, and SOC-ready response sections."
    )


if __name__ == "__main__":
    main()
