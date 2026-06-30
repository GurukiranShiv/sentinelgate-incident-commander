from app.decision_engine import INCIDENT_PROFILES, build_evidence_gates
from app.playbooks import PLAYBOOKS
from app.schemas import IncidentRequest
from app.services.commander import generate_response

REQUIRED_KEYS = {
    "title", "description", "base_confidence", "mitre",
    "investigation_checklist", "containment_plan", "evidence_list", "escalation_summary"
}


def test_all_playbooks_have_required_sections():
    assert len(PLAYBOOKS) >= 10
    for key, playbook in PLAYBOOKS.items():
        missing = REQUIRED_KEYS - set(playbook)
        assert not missing, f"{key} missing {missing}"
        assert len(playbook["investigation_checklist"]) >= 6
        assert len(playbook["containment_plan"]) >= 4
        assert len(playbook["evidence_list"]) >= 5
        assert playbook["base_confidence"] >= 0.97


def test_every_playbook_has_evidence_gates():
    for key in PLAYBOOKS:
        assert key in INCIDENT_PROFILES
        assert len(INCIDENT_PROFILES[key]["storyline"]) >= 4
        assert len(INCIDENT_PROFILES[key]["evidence_gates"]) >= 3


def test_evidence_gate_status_changes_with_input_evidence():
    gates = build_evidence_gates(
        "cloud_iam_abuse",
        ["CloudTrail CreateAccessKey", "unknown source IP", "abnormal user-agent"],
        "No approved change ticket. Suspicious key created from unknown IP.",
    )
    assert gates
    assert any(g["evidence_confidence"] > 0 for g in gates)
    assert all("status" in g for g in gates)


def test_advanced_response_contains_graph_and_architecture_trace():
    response = generate_response(
        IncidentRequest(
            incident_type="ransomware",
            severity="critical",
            environment="Windows enterprise",
            affected_assets=["WIN-FILE-01"],
            indicators=["ransom note", "active encryption", "mass file modification"],
            notes="EDR observed active encryption and ransom note creation.",
            save_case=False,
        )
    )
    assert response["architecture_trace"]["decision_engine"]
    assert response["evidence_graph"]["nodes"]
    assert response["evidence_graph"]["edges"]
    assert response["approval_matrix"]["Red"] or response["approval_matrix"]["Yellow"]


def test_playbook_items_are_actionable():
    weak_words = {"etc", "things", "stuff"}
    for playbook in PLAYBOOKS.values():
        combined = playbook["investigation_checklist"] + playbook["containment_plan"] + playbook["evidence_list"]
        for item in combined:
            assert len(item.strip()) >= 14
            assert not weak_words.intersection({w.strip('.,').lower() for w in item.split()})
