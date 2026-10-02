"""
mitre.py
════════
Single source of truth for MITRE ATT&CK mappings in this project.

Replaces three competing maps that used to disagree:
  - correlation_engine.MITRE_STAGE_MAP
  - timeline_engine.STAGE_MAP
  - predict.MITRE_MAP

Design rules:
  - Benign activity ("Normal Login") maps to NO technique and the "Benign"
    stage. A successful login is never attributed as an attack tactic.
  - Event-ID mappings cite the closest ATT&CK technique; where no good fit
    exists the list is empty (honest gap > wrong technique).
"""

# ── Alert category → [(technique_id, technique_name)] ─────────────────────────

ALERT_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "Brute Force":          [("T1110",     "Brute Force")],
    "Credential Stuffing":  [("T1110.004", "Credential Stuffing")],
    "Password Spray":       [("T1110.003", "Password Spraying")],
    "Suspicious Login":     [("T1078",     "Valid Accounts")],
    "Suspicious Activity":  [("T1059",     "Command and Scripting Interpreter")],
    "Malware Execution":    [("T1059.001", "PowerShell"),
                             ("T1204",     "User Execution")],
    "Credential Dumping":   [("T1003",     "OS Credential Dumping")],
    "Privilege Escalation": [("T1068",     "Exploitation for Privilege Escalation")],
    "Normal Login":         [],   # benign — no technique attributed
}

# ── Alert category → tactic (stage) ───────────────────────────────────────────

ALERT_STAGE: dict[str, str] = {
    "Brute Force":          "Initial Access",
    "Credential Stuffing":  "Initial Access",
    "Password Spray":       "Initial Access",
    "Suspicious Login":     "Initial Access",
    "Suspicious Activity":  "Execution",
    "Malware Execution":    "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Credential Dumping":   "Credential Access",
    "Normal Login":         "Benign",
}

# ── Tactic order for pivot / escalation detection ─────────────────────────────

STAGE_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
_STAGE_IDX = {s: i for i, s in enumerate(STAGE_ORDER)}

# ── Windows/Sysmon event ID → [(technique_id, technique_name)] ────────────────
# Closest-fit mappings; empty where no technique honestly fits.

EVENT_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "4625": [("T1110", "Brute Force")],
    "4648": [("T1078", "Valid Accounts")],
    "4672": [("T1068", "Exploitation for Privilege Escalation")],
    "4688": [("T1059", "Command and Scripting Interpreter")],
    "4698": [("T1053", "Scheduled Task/Job")],
    "4732": [("T1098", "Account Manipulation")],
    "1":    [("T1059", "Command and Scripting Interpreter")],
    "3":    [("T1071", "Application Layer Protocol")],
    "7":    [("T1574", "Hijack Execution Flow")],
    "10":   [("T1003", "OS Credential Dumping")],
    # "11" (file created) and "4624" (successful logon): no technique fits
    # well enough to attribute — left unmapped deliberately.
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def techniques_for_alert(alert_type: str) -> list[str]:
    """Formatted ['T1110 — Brute Force', ...]; [] for benign/unknown."""
    return [f"{tid} — {name}"
            for tid, name in ALERT_TECHNIQUES.get(alert_type, [])]


def techniques_for_event(event_id: str) -> list[str]:
    """Formatted techniques for a Windows/Sysmon event ID."""
    return [f"{tid} — {name}"
            for tid, name in EVENT_TECHNIQUES.get(str(event_id), [])]


def stage_for_alert(alert_type: str) -> str:
    """Tactic stage for an alert category; 'Benign' or 'Unknown'."""
    return ALERT_STAGE.get(alert_type, "Unknown")


def stage_index(stage: str) -> int:
    """Position in the tactic order; -1 for Benign/Unknown (never escalates)."""
    if stage in ("Benign", "Unknown"):
        return -1
    return _STAGE_IDX.get(stage, -1)


def timeline_mapping(alert_type: str) -> tuple[str, str, str, int]:
    """
    (stage, technique_id, technique_name, stage_order) for timeline entries.
    Benign/unknown alerts get empty technique fields.
    """
    stage = stage_for_alert(alert_type)
    techs = ALERT_TECHNIQUES.get(alert_type, [])
    tid, tname = techs[0] if techs else ("", "")
    return stage, tid, tname, stage_index(stage)
