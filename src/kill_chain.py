# MITRE ATT&CK Tactic mapping
TACTIC_MAP = {
    "Brute Force":          "Initial Access",
    "Credential Stuffing":  "Initial Access",
    "Password Spray":       "Initial Access",
    "Suspicious Login":     "Initial Access",
    "Suspicious Activity":  "Execution",
    "Malware Execution":    "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Credential Dumping":   "Credential Access",
    "Normal Login":         None,
}

STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Exfiltration",
]


def map_kill_chain(events: list[dict]) -> list[dict]:
    """
    Returns ordered list of kill chain stages with evidence.
    Each item: {stage, tactic, evidence_count, alert_types}
    """
    stage_evidence: dict[str, list[str]] = {}

    for e in events:
        alert = e.get("alert_type", "Normal Login")
        tactic = TACTIC_MAP.get(alert)

        if tactic:
            stage_evidence.setdefault(tactic, [])
            stage_evidence[tactic].append(alert)

    # Infer additional stages
    detected = set(stage_evidence.keys())

    if "Initial Access" in detected and "Execution" in detected:
        stage_evidence.setdefault("Persistence", ["(inferred)"])

    if "Execution" in detected and "Privilege Escalation" in detected:
        stage_evidence.setdefault("Defense Evasion", ["(inferred)"])

    if "Credential Access" in detected:
        stage_evidence.setdefault("Lateral Movement", ["(inferred)"])
        stage_evidence.setdefault("Exfiltration", ["(inferred)"])

    # Return in MITRE order
    result = []
    for stage in STAGE_ORDER:
        if stage in stage_evidence:
            types = stage_evidence[stage]
            result.append({
                "stage":          stage,
                "evidence_count": len([t for t in types if t != "(inferred)"]),
                "alert_types":    list(set(types)),
                "inferred":       types == ["(inferred)"],
            })

    return result