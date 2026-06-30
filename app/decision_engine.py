from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .playbooks import PLAYBOOKS


@dataclass(frozen=True)
class EvidenceGate:
    action: str
    required_evidence: List[str]
    approval_level: str  # Green / Yellow / Red
    automation: str
    risk_if_wrong: str
    rollback: str


DEFAULT_ASSURANCE_CHECKS = [
    "Action is mapped to a named incident type and not generated from an untrusted prompt alone.",
    "Required evidence is present or the action is marked for human approval.",
    "Destructive or business-impacting actions include rollback guidance.",
    "The report separates confirmed facts from analyst notes and assumptions.",
    "The playbook recommends preserving evidence before cleanup or rebuild actions.",
]

SEVERITY_ESCALATION = {
    "low": "Queue for SOC validation and document in the case record. Escalate if additional affected assets or confirmed compromise appear.",
    "medium": "Assign to SOC L2 for validation, scoping, and containment approval within the current shift.",
    "high": "Escalate to SOC manager and IR lead. Begin containment only after required evidence is preserved.",
    "critical": "Activate major incident process. Notify IR lead, SOC manager, IT operations, legal/privacy, communications, and executive stakeholders as applicable.",
}

SEVERITY_MULTIPLIER = {
    "low": 0.92,
    "medium": 0.96,
    "high": 0.99,
    "critical": 1.0,
}

INCIDENT_PROFILES: Dict[str, Dict[str, Any]] = {
    "phishing_bec": {
        "storyline": ["Suspicious Email", "User Interaction", "Credential Harvesting", "Mailbox Abuse", "Fraud/Data Access"],
        "evidence_gates": [
            EvidenceGate(
                "Quarantine matching emails across all mailboxes",
                ["Email gateway trace", "Message-ID or sender/subject match", "IOC match for URL/domain/hash"],
                "Green",
                "Safe to automate after matching criteria is validated",
                "Overbroad search could quarantine legitimate business email",
                "Release quarantined emails by message trace ID after analyst review",
            ),
            EvidenceGate(
                "Reset password and revoke sessions for suspected user",
                ["Confirmed credential submission", "Suspicious successful login", "MFA fatigue approval", "Impossible travel"],
                "Yellow",
                "Needs SOC L2 approval unless account is actively abused",
                "May interrupt legitimate user access and active business work",
                "Restore access after identity validation and clean MFA registration",
            ),
            EvidenceGate(
                "Notify finance/legal for BEC fraud risk",
                ["Invoice/payment redirection", "Vendor impersonation", "Mailbox rule abuse", "External forwarding"],
                "Red",
                "Requires incident commander approval",
                "Premature escalation may create unnecessary legal/business disruption",
                "Downgrade case after confirming no fraud path or regulated data exposure",
            ),
        ],
    },
    "ransomware": {
        "storyline": ["Initial Access", "Privilege Escalation", "Lateral Movement", "Backup Targeting", "Encryption/Extortion"],
        "evidence_gates": [
            EvidenceGate(
                "Isolate infected endpoint or server",
                ["Active encryption", "Ransom note", "EDR process tree", "Mass file modification", "Known ransomware hash"],
                "Yellow",
                "Can be automated for workstation; approval recommended for server",
                "Could disconnect critical services or break forensic visibility",
                "Remove isolation only after IR lead validates malware eradication and monitoring",
            ),
            EvidenceGate(
                "Disable compromised privileged account",
                ["Suspicious admin logon", "Remote execution using account", "Credential dumping evidence", "Abnormal privilege use"],
                "Yellow",
                "Needs IAM/SOC approval",
                "May break services using shared or legacy admin credentials",
                "Restore via break-glass process after credential rotation",
            ),
            EvidenceGate(
                "Shut down production segment or file server",
                ["Confirmed active spread", "Business owner approval", "Backup status", "IR lead approval"],
                "Red",
                "Human-only containment decision",
                "High business outage and possible evidence loss",
                "Follow approved recovery runbook and bring services back in controlled waves",
            ),
        ],
    },
    "credential_compromise": {
        "storyline": ["Credential Theft", "Suspicious Login", "Session/OAuth Abuse", "Privilege Use", "Data Access"],
        "evidence_gates": [
            EvidenceGate(
                "Revoke sessions and refresh tokens",
                ["Suspicious successful login", "Token reuse", "Impossible travel", "Unrecognized device"],
                "Green",
                "Safe to automate for high-confidence risky sign-in",
                "May log out a legitimate traveling user",
                "Allow re-authentication after identity verification and MFA challenge",
            ),
            EvidenceGate(
                "Remove suspicious OAuth grants and app passwords",
                ["New OAuth consent", "Untrusted application", "Mailbox/file permissions", "Unusual API access"],
                "Yellow",
                "Needs analyst approval if business app ownership is unknown",
                "Could break a legitimate integration",
                "Restore known-good app consent after owner verification",
            ),
            EvidenceGate(
                "Disable account temporarily",
                ["Privileged role", "Active abuse", "Data export", "Multiple failed MFA prompts followed by success"],
                "Red",
                "Requires SOC manager/IAM approval for privileged or executive accounts",
                "Could block critical business or emergency access",
                "Re-enable after password reset, MFA reset, and access review",
            ),
        ],
    },
    "endpoint_malware": {
        "storyline": ["User/Process Trigger", "Execution", "Persistence", "Command & Control", "Containment/Eradication"],
        "evidence_gates": [
            EvidenceGate(
                "Quarantine file or kill malicious process",
                ["EDR detection", "Known malicious hash", "Suspicious process tree", "Sandbox verdict"],
                "Green",
                "Safe to automate when EDR confidence is high",
                "False positive could stop a legitimate business tool",
                "Restore from EDR quarantine after vendor/business validation",
            ),
            EvidenceGate(
                "Network-isolate endpoint",
                ["C2 connection", "Malware execution", "Credential theft behavior", "Lateral movement attempt"],
                "Yellow",
                "Needs analyst approval unless malware is actively spreading",
                "Could interrupt user productivity or remote triage access",
                "Remove isolation after triage package is collected and host is clean",
            ),
            EvidenceGate(
                "Reimage endpoint",
                ["Persistence confirmed", "Rootkit/high-risk malware", "Failed cleanup", "IR approval"],
                "Red",
                "Human-only remediation decision",
                "Can destroy forensic evidence and user data",
                "Restore from known-good image after evidence capture and backup validation",
            ),
        ],
    },
    "cloud_iam_abuse": {
        "storyline": ["API Anomaly", "Key Creation", "Privilege Change", "Resource Enumeration", "Data Access/Exfiltration"],
        "evidence_gates": [
            EvidenceGate(
                "Disable suspicious access key",
                ["CloudTrail CreateAccessKey", "Unknown source IP", "Abnormal user-agent", "No approved change ticket"],
                "Yellow",
                "Needs cloud owner approval unless active abuse is confirmed",
                "Could break production automation if the key belongs to a service account",
                "Create replacement key through approved rotation after owner verification",
            ),
            EvidenceGate(
                "Detach newly added risky IAM policy",
                ["AttachUserPolicy/PutRolePolicy event", "Privilege escalation path", "Unapproved admin action", "Sensitive resource access"],
                "Yellow",
                "Needs IAM/cloud security approval",
                "May interrupt a legitimate emergency change",
                "Reapply policy from infrastructure-as-code after change validation",
            ),
            EvidenceGate(
                "Temporarily restrict role/account with SCP or guardrail",
                ["Active malicious API calls", "Critical asset access", "IR lead approval", "Business impact review"],
                "Red",
                "Human-only cloud containment decision",
                "Could disrupt production workloads across the account",
                "Remove SCP/guardrail in controlled window after access review",
            ),
        ],
    },
    "data_exfiltration": {
        "storyline": ["Collection", "Staging", "Compression", "Outbound Transfer", "External Exposure"],
        "evidence_gates": [
            EvidenceGate(
                "Block destination domain/IP or cloud sharing target",
                ["Large outbound transfer", "Untrusted destination", "DLP/CASB alert", "Confirmed sensitive data path"],
                "Yellow",
                "Needs analyst approval unless destination is known malicious",
                "Could block legitimate partner or backup traffic",
                "Remove block after data owner validates business purpose",
            ),
            EvidenceGate(
                "Revoke external shares and public links",
                ["Public link created", "External recipient", "Sensitive file classification", "Unusual sharing volume"],
                "Green",
                "Safe to automate for clearly sensitive/public exposure",
                "Could interrupt legitimate collaboration",
                "Restore share with expiration and least-privilege access after approval",
            ),
            EvidenceGate(
                "Notify legal/privacy and start breach assessment",
                ["Regulated data involved", "External access confirmed", "Download/export evidence", "Data owner confirmation"],
                "Red",
                "Requires incident commander/legal approval",
                "Premature notification can create unnecessary compliance overhead",
                "Downgrade after confirming no regulated data exposure",
            ),
        ],
    },
    "web_attack": {
        "storyline": ["Recon/Scanning", "Exploit Attempt", "Application Error", "Web Shell/Persistence", "Data Access"],
        "evidence_gates": [
            EvidenceGate(
                "Enable or tighten WAF rule",
                ["Exploit pattern", "WAF/HTTP logs", "Affected route", "False-positive review"],
                "Green",
                "Safe to automate in block mode only for high-confidence signatures",
                "Could block legitimate users or API calls",
                "Switch WAF rule to monitor mode or add exception after validation",
            ),
            EvidenceGate(
                "Take vulnerable endpoint offline",
                ["Successful exploitation", "Business owner approval", "Compensating controls unavailable", "IR lead approval"],
                "Red",
                "Human-only business-impacting decision",
                "Could cause application outage",
                "Restore endpoint after patch, tests, and WAF monitoring",
            ),
            EvidenceGate(
                "Rotate application secrets",
                ["Config exposure", "Web shell access", "Environment dump", "Secret access logs"],
                "Yellow",
                "Needs app owner approval and rotation plan",
                "May break dependent services if rotation is not coordinated",
                "Rollback using secret manager versioning only if compromise is ruled out",
            ),
        ],
    },
    "lateral_movement": {
        "storyline": ["Compromised Host", "Credential Use", "Remote Execution", "Admin Share/Service", "Domain Expansion"],
        "evidence_gates": [
            EvidenceGate(
                "Block lateral movement protocol from source host",
                ["SMB/RDP/WinRM anomaly", "Remote service creation", "Admin share access", "EDR correlation"],
                "Yellow",
                "Needs SOC approval unless actively spreading",
                "Could disrupt administrative or backup operations",
                "Restore network path after host isolation and credential rotation",
            ),
            EvidenceGate(
                "Reset credentials used for movement",
                ["Kerberos/NTLM evidence", "Suspicious logon type", "Credential dumping signs", "Host-to-host reuse"],
                "Yellow",
                "Needs IAM approval for service/admin accounts",
                "May break services or scheduled tasks",
                "Restore through managed secret rotation and service validation",
            ),
            EvidenceGate(
                "Isolate source and destination hosts",
                ["Confirmed remote execution", "Multiple impacted hosts", "Active attacker session", "IR lead approval for servers"],
                "Red",
                "Human approval for servers/domain controllers",
                "May interrupt critical systems and lose volatile attacker session",
                "Remove isolation after memory/log capture and containment verification",
            ),
        ],
    },
    "insider_threat": {
        "storyline": ["Unusual Access", "Policy Violation", "Collection", "External Sharing", "HR/Legal Review"],
        "evidence_gates": [
            EvidenceGate(
                "Preserve user activity evidence under restricted access",
                ["DLP/CASB alert", "File access anomaly", "Data classification", "Case authorization"],
                "Green",
                "Safe to perform with limited evidence access",
                "Mishandled evidence could violate privacy or investigation protocol",
                "Restrict evidence access and record chain-of-custody corrections",
            ),
            EvidenceGate(
                "Revoke external shares or unmanaged device sessions",
                ["External share", "Sensitive data", "No approved business need", "Data owner validation"],
                "Yellow",
                "Needs data owner or insider-risk approval",
                "Could disrupt legitimate collaboration or tip off user",
                "Restore approved sharing after legal/HR review",
            ),
            EvidenceGate(
                "Suspend user access",
                ["Active exfiltration", "HR/legal approval", "Manager coordination", "Business continuity plan"],
                "Red",
                "Human-only HR/legal decision unless active harm is occurring",
                "Could create employment/legal risk and disrupt business",
                "Reinstate least-privilege access after formal decision",
            ),
        ],
    },
    "vulnerability_exploitation": {
        "storyline": ["Exposure", "Exploit Attempt", "Post-Exploitation", "Containment", "Patch/Verification"],
        "evidence_gates": [
            EvidenceGate(
                "Deploy virtual patch or WAF/IPS signature",
                ["CVE/product version", "Exploit pattern", "Affected endpoint", "False-positive review"],
                "Green",
                "Safe to automate in monitor mode; block mode after validation",
                "Could block legitimate application behavior",
                "Roll back rule or change to monitor mode after testing",
            ),
            EvidenceGate(
                "Restrict internet exposure of affected service",
                ["Internet-facing asset", "Active exploitation", "Business owner approval", "Compensating controls unavailable"],
                "Red",
                "Human approval required",
                "Could cause customer or business outage",
                "Restore exposure after patch, rescan, and log validation",
            ),
            EvidenceGate(
                "Rotate secrets on affected system",
                ["Successful exploitation likely", "Secret storage on host", "Post-exploitation artifact", "IR approval"],
                "Yellow",
                "Needs service owner approval and coordinated rotation",
                "Can break integrations if dependencies are unknown",
                "Use secret manager rollback only if exposure is ruled out",
            ),
        ],
    },
}


def _profile(incident_type: str) -> Dict[str, Any]:
    return INCIDENT_PROFILES.get(
        incident_type,
        {
            "storyline": ["Alert", "Scope", "Contain", "Eradicate", "Recover"],
            "evidence_gates": [],
        },
    )


def normalize_items(items: List[str]) -> List[str]:
    return [item.strip() for item in items if item and item.strip()]


def match_evidence(required: List[str], available: List[str], notes: str | None) -> Tuple[List[str], List[str], float]:
    """Very small deterministic matcher for demo purposes.

    It does not claim detection truth. It checks whether the analyst-supplied
    indicators/notes contain terms related to required evidence.
    """
    haystack = " ".join(available + ([notes] if notes else [])).lower()
    verified: List[str] = []
    missing: List[str] = []
    for item in required:
        tokens = [t.strip(".,:/_-()[]").lower() for t in item.split() if len(t.strip(".,:/_-()[]")) >= 4]
        if any(token in haystack for token in tokens):
            verified.append(item)
        else:
            missing.append(item)
    confidence = round(len(verified) / max(len(required), 1), 2)
    return verified, missing, confidence


def build_evidence_gates(incident_type: str, indicators: List[str], notes: str | None) -> List[Dict[str, Any]]:
    gates: List[EvidenceGate] = _profile(incident_type)["evidence_gates"]
    output = []
    for gate in gates:
        verified, missing, evidence_confidence = match_evidence(gate.required_evidence, indicators, notes)
        if gate.approval_level == "Green" and evidence_confidence >= 0.50:
            status = "Automation Ready"
        elif evidence_confidence >= 0.50:
            status = "Evidence Partially Verified - Approval Required"
        else:
            status = "Missing Evidence - Do Not Execute Yet"
        output.append(
            {
                "action": gate.action,
                "required_evidence": gate.required_evidence,
                "verified_evidence": verified,
                "missing_evidence": missing,
                "evidence_confidence": evidence_confidence,
                "approval_level": gate.approval_level,
                "automation": gate.automation,
                "risk_if_wrong": gate.risk_if_wrong,
                "rollback": gate.rollback,
                "status": status,
            }
        )
    return output


def build_attack_storyline(incident_type: str) -> List[str]:
    return list(_profile(incident_type)["storyline"])


def build_approval_matrix(evidence_gates: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    matrix = {"Green": [], "Yellow": [], "Red": []}
    for gate in evidence_gates:
        matrix.setdefault(gate["approval_level"], []).append(gate["action"])
    return matrix


def quality_score(playbook: Dict[str, Any], severity: str, indicators: List[str], affected_assets: List[str], notes: str | None, gates: List[Dict[str, Any]]) -> float:
    """Transparent playbook coverage score, not guaranteed real-world accuracy."""
    score = float(playbook.get("base_confidence", 0.95)) * SEVERITY_MULTIPLIER[severity]
    if indicators:
        score += 0.006
    if affected_assets:
        score += 0.006
    if notes and len(notes.strip()) > 20:
        score += 0.004
    if gates:
        gate_conf = sum(g["evidence_confidence"] for g in gates) / len(gates)
        score += min(gate_conf * 0.01, 0.01)
    return round(min(score, 0.995), 3)


def prioritized_actions(playbook: Dict[str, Any], severity: str, gates: List[Dict[str, Any]]) -> List[str]:
    items: List[str] = []
    if severity in {"high", "critical"}:
        items.append("Open a war-room bridge and assign incident commander, scribe, evidence owner, containment owner, and communications owner.")
    ready_actions = [g for g in gates if g["status"] == "Automation Ready"]
    approval_actions = [g for g in gates if "Approval Required" in g["status"]]
    missing_actions = [g for g in gates if "Missing Evidence" in g["status"]]
    items.extend([f"Execute approved low-risk action: {g['action']}" for g in ready_actions[:2]])
    items.extend([f"Prepare for approval: {g['action']}" for g in approval_actions[:2]])
    if missing_actions:
        items.append(f"Collect missing evidence before containment: {missing_actions[0]['action']}.")
    if not ready_actions and not approval_actions:
        items.extend(playbook["containment_plan"][:3])
    if severity == "critical":
        items.append("Freeze destructive remediation until legal/IR lead approves evidence preservation and recovery sequence.")
    return items


def timeline_template() -> List[Dict[str, str]]:
    return [
        {"phase": "Triage", "goal": "Validate alert, classify severity, identify owner, and start the case timeline."},
        {"phase": "Scope", "goal": "Find affected users, hosts, cloud assets, data, and related indicators."},
        {"phase": "Evidence Gate", "goal": "Check whether each containment action has enough evidence and the right approval level."},
        {"phase": "Contain", "goal": "Stop active harm while preserving evidence and avoiding unnecessary business disruption."},
        {"phase": "Eradicate", "goal": "Remove attacker access, malware, persistence, exposed secrets, or vulnerable paths."},
        {"phase": "Recover", "goal": "Restore services safely and monitor for recurrence."},
        {"phase": "Lessons Learned", "goal": "Document root cause, detection gaps, control improvements, and evidence package."},
    ]
