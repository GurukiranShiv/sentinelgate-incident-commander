from __future__ import annotations

from typing import Dict, List, Any

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "phishing_bec": {
        "title": "Phishing / Business Email Compromise",
        "description": "Suspicious email, credential harvesting, mailbox rule abuse, invoice fraud, or user-reported phishing.",
        "base_confidence": 0.982,
        "mitre": ["Initial Access", "Credential Access", "Defense Evasion", "Collection"],
        "investigation_checklist": [
            "Confirm reporter, received timestamp, sender domain, reply-to address, URLs, attachments, and affected recipients.",
            "Pull full email headers and inspect SPF, DKIM, DMARC, return-path, message-id, and originating IP reputation.",
            "Detonate URLs and attachments in a sandbox or safe analysis environment; never open directly on analyst workstation.",
            "Search email gateway/SIEM for the same sender, subject, URL, attachment hash, and campaign indicators across all mailboxes.",
            "Check identity logs for failed/successful logins, impossible travel, MFA fatigue, new device registrations, OAuth grants, and mailbox rule creation.",
            "Review mailbox forwarding rules, delegated access, sent items, deleted items, and suspicious invoice/payment conversations.",
            "Identify whether credentials were entered or attachment was executed; interview user only after collecting volatile evidence.",
            "Map observed behavior to ATT&CK techniques and determine if this is phishing only, credential theft, or confirmed BEC."
        ],
        "containment_plan": [
            "Quarantine the email across all recipients and block sender/domain/URL/hash at email gateway, DNS, proxy, and EDR where applicable.",
            "If credential exposure is suspected, revoke sessions, reset password, require MFA re-registration, and remove suspicious OAuth grants.",
            "Disable malicious inbox rules and forwarding; preserve mailbox contents before cleanup if fraud or legal review is possible.",
            "Notify finance/AP team if payment redirection, invoice fraud, or vendor impersonation is involved.",
            "Monitor for follow-on logins, lateral movement, and new phishing campaigns using the same infrastructure."
        ],
        "evidence_list": [
            "Original email .eml/.msg with complete headers",
            "URLs, domains, IPs, attachment filenames, hashes, sandbox report",
            "Email gateway trace and quarantine logs",
            "Identity provider sign-in logs, MFA events, token/session revocation records",
            "Mailbox audit logs, forwarding rules, OAuth consent logs",
            "User statement and timeline of clicks, submissions, or downloads"
        ],
        "escalation_summary": "Escalate to SOC L2 if multiple recipients, confirmed credential submission, malicious attachment execution, or suspicious sign-in activity is observed. Escalate to IR lead and Legal/Privacy for BEC, fraud, regulated data exposure, or external notification concerns. Include sender infrastructure, affected users, containment actions, and whether credentials were reset."
    },
    "ransomware": {
        "title": "Ransomware / Mass Encryption",
        "description": "Encryption activity, ransom note, suspicious backup deletion, lateral movement, or malware behavior consistent with ransomware.",
        "base_confidence": 0.988,
        "mitre": ["Execution", "Privilege Escalation", "Lateral Movement", "Impact", "Defense Evasion"],
        "investigation_checklist": [
            "Identify first alerted host, encryption start time, ransom note name, impacted shares, and current spread scope.",
            "Collect EDR process tree, parent/child processes, command lines, hashes, network connections, and signed/unsigned binary metadata.",
            "Search for common precursor activity: phishing, exposed RDP/VPN, credential dumping, PsExec/WinRM, GPO changes, backup deletion, and discovery commands.",
            "Check domain controllers, file servers, backup servers, and privileged accounts for suspicious authentication patterns.",
            "Determine whether data exfiltration occurred before encryption by reviewing proxy, DNS, firewall, cloud storage, and DLP logs.",
            "Preserve ransom notes, malware samples, memory snapshots when feasible, and endpoint triage packages.",
            "Classify business impact: affected critical services, safety impact, recovery point objective, and backup integrity.",
            "Build a timeline from initial access to execution and map to MITRE ATT&CK tactics."
        ],
        "containment_plan": [
            "Immediately isolate infected and suspected hosts using EDR network containment or switch/VLAN controls.",
            "Disable compromised privileged accounts and rotate service account credentials after understanding dependencies.",
            "Block identified command-and-control, payload hashes, suspicious tools, and lateral movement protocols where safe.",
            "Protect backups: disconnect backup repositories from production access paths and validate immutable/offline copies.",
            "Do not wipe systems until forensic evidence and business recovery requirements are approved by IR leadership."
        ],
        "evidence_list": [
            "EDR telemetry, process trees, file modification timelines",
            "Ransom note, encrypted file samples, malware hashes, dropped tools",
            "Authentication logs from VPN, AD, Entra ID/Okta, domain controllers",
            "Windows Event Logs: Security, System, PowerShell, Sysmon if available",
            "Firewall/proxy/DNS logs showing C2 or exfiltration",
            "Backup deletion logs, VSSAdmin/WBAdmin commands, cloud backup audit logs"
        ],
        "escalation_summary": "Treat as high or critical severity. Escalate immediately to IR lead, SOC manager, IT operations, legal/privacy, executive crisis team, cyber insurance contact, and communications lead. Include current blast radius, whether encryption is active, systems isolated, backup status, suspected initial access, and data exfiltration confidence."
    },
    "credential_compromise": {
        "title": "Credential Compromise / Account Takeover",
        "description": "Impossible travel, suspicious login, MFA push abuse, password spray, token theft, or abnormal privileged account use.",
        "base_confidence": 0.984,
        "mitre": ["Credential Access", "Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "investigation_checklist": [
            "Confirm account owner, role, privilege level, recent travel, expected devices, and normal login pattern.",
            "Review successful and failed logins by IP, ASN, geolocation, device, user agent, authentication method, and MFA result.",
            "Check for password spraying across multiple accounts from same IP, ASN, device fingerprint, or user agent.",
            "Inspect new MFA devices, app passwords, recovery email/phone changes, OAuth grants, and risky session tokens.",
            "Review privileged actions: role assignments, mailbox access, cloud API calls, source code access, data downloads, and admin console changes.",
            "Search for lateral movement using the account across VPN, RDP, SMB, SaaS apps, and cloud consoles.",
            "Determine whether compromise is password-based, token-based, MFA fatigue, OAuth abuse, or insider misuse.",
            "Document timeline from first suspicious authentication to containment."
        ],
        "containment_plan": [
            "Revoke active sessions and refresh tokens; force password reset from a clean device.",
            "Temporarily disable the account if privileged or actively abused.",
            "Remove suspicious MFA factors, app passwords, OAuth grants, API keys, and mailbox rules.",
            "Block malicious IPs/ASNs cautiously; prefer conditional access risk controls where available.",
            "Increase monitoring for related accounts, shared credentials, and administrator role changes."
        ],
        "evidence_list": [
            "Identity sign-in logs, MFA logs, conditional access decisions",
            "Risky user/risky sign-in reports",
            "OAuth consent and token activity logs",
            "Administrative audit logs and privilege assignment records",
            "VPN, SSO, SaaS, and cloud console logs",
            "User confirmation of travel/device legitimacy"
        ],
        "escalation_summary": "Escalate to SOC L2 for confirmed unauthorized login, privileged account activity, MFA bypass, token theft, or signs of lateral movement. Escalate to IAM, cloud administrators, and Legal/Privacy if sensitive data was accessed or exported. Include account risk, access scope, suspicious IP/device, containment completed, and outstanding access review items."
    },
    "endpoint_malware": {
        "title": "Endpoint Malware / Suspicious Process",
        "description": "Malware alert, suspicious process chain, persistence, unusual PowerShell, command-and-control, or EDR detection.",
        "base_confidence": 0.981,
        "mitre": ["Execution", "Persistence", "Defense Evasion", "Command and Control", "Discovery"],
        "investigation_checklist": [
            "Identify hostname, user, detection name, severity, file path, hash, process tree, and whether EDR already blocked/quarantined it.",
            "Review parent process, command line, script block logs, loaded modules, network connections, and persistence locations.",
            "Check for common abuse: PowerShell encoded commands, WMI, scheduled tasks, registry run keys, LOLBins, macro execution, and unsigned binaries.",
            "Correlate hash/domain/IP with threat intelligence and internal sightings across hosts.",
            "Review recent downloads, email attachments, browser history, USB activity, and software installation events.",
            "Determine if malware achieved execution, persistence, privilege escalation, C2, credential access, or data staging.",
            "Collect triage package, suspicious binaries/scripts, memory sample where necessary, and event logs.",
            "Search for same indicators across EDR, SIEM, proxy, DNS, and file shares."
        ],
        "containment_plan": [
            "Isolate host if malware executed, C2 established, credentials may be exposed, or spread is suspected.",
            "Quarantine/delete malicious files only after hashes, paths, and metadata are preserved.",
            "Kill malicious processes and remove persistence mechanisms through EDR or approved endpoint tools.",
            "Reset passwords for users whose credentials may have been accessed on the endpoint.",
            "Patch exploited software and block indicators across EDR, DNS, proxy, and firewall."
        ],
        "evidence_list": [
            "EDR alert details, process tree, command line, hash, file path",
            "Suspicious binaries/scripts and metadata",
            "Windows Security, Sysmon, PowerShell, Application, and System logs",
            "DNS/proxy/firewall connections from endpoint",
            "Persistence artifacts: scheduled tasks, services, registry keys, startup folders",
            "Memory image or triage collection where approved"
        ],
        "escalation_summary": "Escalate when malware executed, persistence exists, C2 is confirmed, credential access is suspected, or multiple hosts are affected. Notify endpoint engineering for remediation and IR lead if containment requires host isolation, forensic imaging, or enterprise-wide hunting. Include process tree, hash, scope, containment state, and known ATT&CK mapping."
    },
    "cloud_iam_abuse": {
        "title": "Cloud IAM Abuse / Unauthorized API Activity",
        "description": "Suspicious AWS/Azure/GCP API calls, privilege escalation, access key abuse, role assumption anomalies, or cloud resource tampering.",
        "base_confidence": 0.983,
        "mitre": ["Initial Access", "Privilege Escalation", "Defense Evasion", "Discovery", "Exfiltration"],
        "investigation_checklist": [
            "Identify cloud account/subscription/project, principal, API call, source IP, region, user agent, and event time.",
            "Review identity history: role assumptions, access key creation, policy attachment, MFA changes, group membership, and console logins.",
            "Check for discovery and staging actions: ListBuckets, DescribeInstances, GetCallerIdentity, storage enumeration, snapshot creation, and secret retrieval.",
            "Inspect high-risk changes: disabling logs, deleting trails, modifying security groups, creating public storage, adding admin policies, or creating backdoor users.",
            "Correlate CloudTrail/Azure Activity/GCP Audit logs with GuardDuty/Defender/SCC findings and IAM Access Analyzer where available.",
            "Determine if the activity came from CI/CD, automation, expected admin task, compromised key, or external actor.",
            "Review data access logs for object downloads, database snapshots, secrets access, and unusual egress.",
            "Build a cloud timeline and map actions to ATT&CK Cloud techniques."
        ],
        "containment_plan": [
            "Disable or rotate compromised access keys; revoke sessions for impacted identity.",
            "Detach unauthorized policies and remove unknown users, roles, trust relationships, and service principals.",
            "Re-enable or protect cloud logging; validate audit trail integrity and storage retention.",
            "Restrict source IPs, enforce MFA/conditional access, and temporarily limit high-risk API actions if business-safe.",
            "Snapshot evidence before deleting attacker-created resources; preserve logs in a separate protected account/bucket."
        ],
        "evidence_list": [
            "CloudTrail/Azure Activity/GCP Admin Activity logs",
            "Identity provider logs and role assumption records",
            "Access key creation/use metadata and user agents",
            "Cloud security findings from GuardDuty/Defender/SCC",
            "IAM policy diffs, group/role membership changes, trust policy changes",
            "Storage/object access logs, snapshot records, secret access logs"
        ],
        "escalation_summary": "Escalate to cloud security/IAM immediately when admin privileges, exposed keys, logging tampering, public storage exposure, or data access is suspected. Escalate to IR lead and Legal/Privacy for confirmed data exfiltration or regulated data access. Include principal, API actions, regions, source IP/user agent, containment actions, and remaining blast-radius questions."
    },
    "data_exfiltration": {
        "title": "Data Exfiltration / Unusual Egress",
        "description": "Large outbound transfer, cloud storage download, unusual SaaS export, DNS tunneling, or DLP alert.",
        "base_confidence": 0.979,
        "mitre": ["Collection", "Command and Control", "Exfiltration", "Defense Evasion"],
        "investigation_checklist": [
            "Confirm data source, user/service account, destination, volume, protocol, time window, and business justification.",
            "Review DLP, proxy, CASB, firewall, DNS, SaaS audit, database, and endpoint logs for correlated transfer activity.",
            "Classify data type: public, internal, confidential, regulated, credentials, source code, customer data, or intellectual property.",
            "Identify staging behavior: compression, archiving, unusual temp directories, rclone/MEGA/Dropbox tools, database dumps, or cloud snapshots.",
            "Check for preceding compromise indicators: credential abuse, malware, web shell, cloud IAM changes, or insider policy violations.",
            "Determine whether transfer was blocked, partially completed, completed, or unknown.",
            "Preserve network flow metadata, file audit logs, and object access logs before retention expires.",
            "Estimate blast radius: exact files, records, users, tables, buckets, repositories, or mailboxes accessed."
        ],
        "containment_plan": [
            "Block or rate-limit destination domains/IPs and suspend suspicious sessions if exfiltration is active.",
            "Disable compromised accounts or restrict data access privileges pending review.",
            "Revoke sharing links, external collaborators, API tokens, and cloud storage access where misused.",
            "Preserve affected data repositories and logs for legal/privacy review.",
            "Implement temporary DLP/CASB rules for similar patterns while full remediation is planned."
        ],
        "evidence_list": [
            "DLP/CASB alert payloads and matched policies",
            "Proxy/firewall/NetFlow/DNS logs",
            "SaaS/cloud object access logs and export events",
            "Database audit logs and query/export history",
            "Endpoint evidence of staging/compression tools",
            "Data inventory/classification records and affected object list"
        ],
        "escalation_summary": "Escalate to IR lead, data owner, Legal/Privacy, and compliance team when confidential or regulated data may have left the environment. Include data type, estimated volume, destination, account used, completion confidence, containment steps, and whether notification analysis is required."
    },
    "web_attack": {
        "title": "Web Application Attack / WAF Alert",
        "description": "SQL injection, XSS, RCE attempt, path traversal, web shell, credential stuffing, or abnormal web traffic.",
        "base_confidence": 0.978,
        "mitre": ["Initial Access", "Execution", "Persistence", "Credential Access", "Exfiltration"],
        "investigation_checklist": [
            "Identify affected application, URL, HTTP method, source IP/ASN, user account/session, payload, status code, and WAF action.",
            "Review web server, application, WAF, CDN, load balancer, and authentication logs for related attempts.",
            "Determine if attack was blocked, reached application logic, caused errors, created files, changed data, or returned sensitive content.",
            "Look for exploitation signs: unexpected child processes, web shell files, suspicious uploads, unusual outbound connections, and modified application files.",
            "Check vulnerability context: recent deploys, known CVEs, vulnerable endpoints, exposed admin panels, and missing input validation.",
            "Correlate repeated attempts across IPs/user agents to distinguish scanning, credential stuffing, exploitation, or post-exploitation.",
            "Validate whether accounts were compromised or data was accessed through the application.",
            "Capture payload safely and create detection/blocking rules based on normalized indicators."
        ],
        "containment_plan": [
            "Enable or tighten WAF rule in block mode for confirmed malicious payloads after testing for false positives.",
            "Temporarily restrict affected endpoint/admin panel by IP, auth requirement, or feature flag where business-safe.",
            "Disable compromised accounts or force password resets for credential stuffing outcomes.",
            "Remove web shells only after preserving file metadata, content, access logs, and process evidence.",
            "Patch vulnerable code/dependency and rotate exposed secrets if server-side compromise is possible."
        ],
        "evidence_list": [
            "WAF/CDN/load balancer logs and request payload samples",
            "Web/application server logs and error traces",
            "Authentication/session logs",
            "File integrity changes, uploaded files, web shell artifacts",
            "Application deployment and dependency version records",
            "Database query logs or affected record list if data access occurred"
        ],
        "escalation_summary": "Escalate to application owner and SOC L2 for successful exploitation indicators, authentication bypass, web shell, data access, or persistent attack traffic. Escalate to IR lead and Legal/Privacy if customer or regulated data may be exposed. Include endpoint, payload, WAF decision, exploit success confidence, and proposed patch/block action."
    },
    "lateral_movement": {
        "title": "Lateral Movement / Internal Reconnaissance",
        "description": "SMB/RDP/WinRM/PsExec movement, internal scanning, remote service creation, Kerberoasting, or admin share abuse.",
        "base_confidence": 0.985,
        "mitre": ["Discovery", "Credential Access", "Lateral Movement", "Privilege Escalation", "Command and Control"],
        "investigation_checklist": [
            "Identify source host, destination hosts, account used, protocol, ports, process, and first observed time.",
            "Review authentication logs for logon types, admin group usage, Kerberos anomalies, NTLM spikes, and failed attempts.",
            "Inspect EDR telemetry for PsExec, WMI, WinRM, remote services, scheduled tasks, SMB admin share writes, and discovery commands.",
            "Check whether the source host is compromised and whether credentials were dumped or reused.",
            "Map affected host relationships: workstation-to-server, server-to-server, domain controller access, and privileged path exposure.",
            "Search for common tooling: net.exe, nltest, whoami, ipconfig, adfind, bloodhound collectors, rundll32, powershell remoting.",
            "Review firewall/NetFlow/Zeek logs for internal scanning and unusual east-west traffic.",
            "Build a movement graph showing source, account, destination, protocol, and timestamps."
        ],
        "containment_plan": [
            "Isolate confirmed compromised source hosts and block active lateral movement paths.",
            "Disable or reset abused accounts; rotate credentials for local admins and service accounts where exposed.",
            "Restrict RDP/SMB/WinRM/PsExec usage to admin jump hosts where possible.",
            "Remove attacker-created services, scheduled tasks, and remote tools after evidence capture.",
            "Increase monitoring on domain controllers, privileged groups, and critical servers."
        ],
        "evidence_list": [
            "Windows Security logs: 4624, 4625, 4672, 4688, 4697, 7045 where available",
            "EDR process trees and remote execution telemetry",
            "Sysmon logs and PowerShell operational logs",
            "Firewall/NetFlow/Zeek east-west traffic records",
            "Active Directory group changes and Kerberos events",
            "Remote service, scheduled task, admin share, and SMB access artifacts"
        ],
        "escalation_summary": "Escalate immediately to SOC L2/IR when lateral movement touches servers, domain controllers, privileged accounts, or multiple hosts. Include movement graph, account used, protocols, compromised source confidence, isolated systems, and credential rotation requirements."
    },
    "insider_threat": {
        "title": "Insider Threat / Data Misuse",
        "description": "Unusual employee data access, policy violation, mass downloads, unauthorized sharing, or suspicious offboarding behavior.",
        "base_confidence": 0.972,
        "mitre": ["Collection", "Exfiltration", "Defense Evasion"],
        "investigation_checklist": [
            "Confirm alert source, employee role, manager, access level, business need, HR/offboarding status, and data classification.",
            "Review file access, SaaS audit logs, email forwarding, USB activity, cloud sync, printing, screenshots, and external sharing.",
            "Compare behavior to baseline: normal working hours, usual repositories, typical transfer volume, and peer group activity.",
            "Check for policy exception, approved project, legal hold, investigation sensitivity, and need-to-know restrictions.",
            "Avoid tipping off the user before HR/Legal approval; preserve evidence with strict access control.",
            "Determine whether activity is negligent, compromised-account behavior, or intentional misuse.",
            "Identify exact documents, records, recipients, devices, and external destinations involved.",
            "Maintain chain of custody and document who accessed evidence."
        ],
        "containment_plan": [
            "Coordinate with HR, Legal, and management before disabling access unless active harm is occurring.",
            "Suspend or reduce access to sensitive repositories according to approved insider response process.",
            "Revoke external shares, sync tokens, unmanaged device access, and mailbox forwarding if misused.",
            "Preserve endpoint and SaaS logs; avoid destructive cleanup until legal review is complete.",
            "Apply additional monitoring or DLP rules for high-risk repositories."
        ],
        "evidence_list": [
            "File access and SaaS audit logs",
            "DLP/CASB alerts and policy matches",
            "USB, print, screenshot, cloud sync, and email forwarding records",
            "HR/offboarding status and access approval records",
            "Data classification and exact object list",
            "Chain-of-custody notes and evidence access logs"
        ],
        "escalation_summary": "Escalate to HR, Legal, insider risk team, data owner, and SOC leadership. Do not broadly notify technical teams unless approved. Include user role, data type, evidence summary, active risk, containment recommendation, and chain-of-custody status."
    },
    "vulnerability_exploitation": {
        "title": "Vulnerability Exploitation / Public CVE",
        "description": "Known exploited vulnerability, internet-facing exploit attempt, suspicious post-exploitation, or emergency patch response.",
        "base_confidence": 0.976,
        "mitre": ["Initial Access", "Execution", "Privilege Escalation", "Persistence", "Defense Evasion"],
        "investigation_checklist": [
            "Identify CVE/product/version, affected asset owner, internet exposure, exploit availability, and observed exploit indicators.",
            "Review vulnerability scanner, EASM, CMDB, WAF, IDS/IPS, EDR, and application logs for exposure and exploitation evidence.",
            "Determine whether traffic was scanning, attempted exploitation, or successful post-exploitation.",
            "Check for vendor-specific IOCs, vulnerable endpoints, suspicious files, new accounts, child processes, and outbound callbacks.",
            "Prioritize assets by exploitability, criticality, data sensitivity, internet exposure, and known exploitation status.",
            "Validate whether compensating controls exist: WAF rule, virtual patching, network ACLs, EDR prevention, or disabled feature.",
            "Create remediation tracker with owner, patch version, mitigation, due date, and verification evidence.",
            "Perform enterprise-wide hunt for affected product/version and indicators."
        ],
        "containment_plan": [
            "Apply vendor patch or recommended mitigation based on change-control priority.",
            "If active exploitation is suspected, restrict external access or isolate affected service until validated.",
            "Deploy WAF/IPS/EDR virtual patching signatures where available.",
            "Rotate secrets and credentials stored on affected systems if compromise is possible.",
            "Verify remediation with rescans, log review, and exploit-path testing in an approved environment."
        ],
        "evidence_list": [
            "Scanner results, asset inventory, software/version evidence",
            "Vendor advisory references and IOC list",
            "WAF/IDS/IPS/application logs showing exploit attempts",
            "EDR telemetry from affected systems",
            "Patch/mitigation change records and rescan proof",
            "Post-exploitation artifacts, accounts, files, callbacks, or web shells"
        ],
        "escalation_summary": "Escalate to vulnerability management, asset owner, SOC L2, and IR lead if exploitation may have succeeded or asset is business-critical/internet-facing. Include CVE, affected assets, exposure, exploit evidence, containment/patch status, and verification plan."
    }
}


def list_incident_types() -> List[Dict[str, str]]:
    return [
        {"id": key, "title": value["title"], "description": value["description"]}
        for key, value in PLAYBOOKS.items()
    ]
