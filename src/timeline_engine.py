"""
timeline_engine.py
══════════════════
Attack Timeline Intelligence Engine

Converts raw event sequences into structured, stage-annotated timelines:
  - Maps events to MITRE ATT&CK stages
  - Detects escalation pivot points
  - Identifies attack progression patterns
  - Calculates dwell time between stages

Output:
  - List of structured TimelineEntry dicts
  - Timeline metadata (duration, stage count, pivot count)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK STAGE MAPPING
# ══════════════════════════════════════════════════════════════════════════════

# Maps alert_type → (tactic, technique_id, technique_name, tactic_order)
STAGE_MAP: dict[str, tuple[str, str, str, int]] = {
    "Normal Login":         ("Initial Access",       "T1078",     "Valid Accounts",                     1),
    "Brute Force":          ("Initial Access",       "T1110",     "Brute Force",                        1),
    "Credential Stuffing":  ("Initial Access",       "T1110.004", "Credential Stuffing",                1),
    "Password Spray":       ("Initial Access",       "T1110.003", "Password Spraying",                  1),
    "Suspicious Login":     ("Initial Access",       "T1078",     "Valid Accounts (Suspicious)",        1),
    "Suspicious Activity":  ("Execution",            "T1059",     "Command & Scripting Interpreter",    2),
    "Malware Execution":    ("Execution",            "T1059.001", "PowerShell / Script Execution",      2),
    "Privilege Escalation": ("Privilege Escalation", "T1068",     "Exploitation for PrivEsc",           3),
    "Credential Dumping":   ("Credential Access",    "T1003",     "OS Credential Dumping",              4),
}

# Tactic order (for escalation detection)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_IDX = {t: i for i, t in enumerate(TACTIC_ORDER)}

# Color coding for UI
STAGE_COLORS = {
    "Initial Access":       "#f0883e",
    "Execution":            "#da3633",
    "Persistence":          "#b91c1c",
    "Privilege Escalation": "#7f1d1d",
    "Defense Evasion":      "#9333ea",
    "Credential Access":    "#7c3aed",
    "Discovery":            "#d97706",
    "Lateral Movement":     "#dc2626",
    "Exfiltration":         "#991b1b",
    "Impact":               "#450a0a",
    "Unknown":              "#6b7280",
}

SEVERITY_FOR_STAGE = {
    "Initial Access":       "Medium",
    "Execution":            "High",
    "Persistence":          "High",
    "Privilege Escalation": "Critical",
    "Defense Evasion":      "High",
    "Credential Access":    "Critical",
    "Discovery":            "Medium",
    "Lateral Movement":     "Critical",
    "Exfiltration":         "Critical",
    "Impact":               "Critical",
    "Unknown":              "Low",
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TimelineEntry:
    index:           int
    timestamp:       str
    timestamp_rel:   str       # e.g. "T+5m30s" relative to first event
    event_id:        str
    alert_type:      str
    source_ip:       str
    failed_logins:   int
    location:        str
    device:          str
    # MITRE
    stage:           str       # tactic name
    technique_id:    str
    technique_name:  str
    stage_order:     int       # for sorting/comparison
    # Analysis
    is_pivot:        bool      # stage advanced
    is_escalation:   bool      # stage order is higher than any previous
    is_anomaly:      bool      # marked by anomaly detection
    risk_contribution: int     # 0–100, how much this event contributed
    color:           str       # hex color for UI
    severity:        str
    # Dwell time (time since last event in same stage)
    dwell_seconds:   Optional[int]
    dwell_label:     str       # "T+5m" etc.

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TimelineMeta:
    total_events:    int
    unique_stages:   list[str]
    stage_count:     int
    pivot_count:     int
    escalation_count: int
    first_ts:        str
    last_ts:         str
    duration_seconds: int
    duration_label:  str
    attack_progression: list[str]   # ordered stage names
    has_full_chain:  bool
    completeness_pct: int           # % of known 6-stage chain covered

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TimelineResult:
    entries: list[TimelineEntry]
    meta:    TimelineMeta

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "meta":    self.meta.to_dict(),
        }

    def to_plain_list(self) -> list[dict]:
        """Return just the entries as dicts (for JSON APIs)."""
        return [e.to_dict() for e in self.entries]


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_ts(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def _rel_time(base: datetime, current: datetime) -> str:
    delta = int((current - base).total_seconds())
    if delta < 0:
        return "T-0"
    h, rem = divmod(delta, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"T+{h}h{m:02d}m"
    elif m:
        return f"T+{m}m{s:02d}s"
    else:
        return f"T+{s}s"


def _dwell_label(seconds: Optional[int]) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    return f"{m}m{s:02d}s"


def _duration_label(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


def _risk_contribution(alert_type: str, failed_logins: int,
                       is_pivot: bool) -> int:
    """Estimate how much this single event contributed to overall risk."""
    base = {
        "Credential Dumping":   40,
        "Privilege Escalation": 35,
        "Malware Execution":    30,
        "Brute Force":          20,
        "Credential Stuffing":  22,
        "Password Spray":       18,
        "Suspicious Activity":  15,
        "Suspicious Login":     12,
        "Normal Login":          5,
    }.get(alert_type, 10)

    base += min(int(failed_logins * 0.5), 20)
    if is_pivot:
        base += 15

    return min(base, 100)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_timeline(raw_logs: list[dict]) -> TimelineResult:
    """
    Build an intelligent, annotated attack timeline from raw log events.

    Parameters
    ----------
    raw_logs : list[dict]
        Each dict: timestamp, alert_type, source_ip, failed_logins,
                   event_id, location, device

    Returns
    -------
    TimelineResult
    """
    if not raw_logs:
        meta = TimelineMeta(0, [], 0, 0, 0, "", "", 0, "0s", [], False, 0)
        return TimelineResult([], meta)

    # Parse and sort by time
    now = datetime.now(timezone.utc)
    events = []
    for i, log in enumerate(raw_logs):
        ts = log.get("timestamp") or (now - timedelta(seconds=(len(raw_logs)-i)*30)).isoformat()
        events.append((ts, log))

    events.sort(key=lambda x: _parse_ts(x[0]))

    first_dt = _parse_ts(events[0][0])
    last_dt  = _parse_ts(events[-1][0])

    entries: list[TimelineEntry] = []
    max_stage_seen = -1
    stage_last_ts: dict[str, datetime] = {}

    for idx, (ts, log) in enumerate(events):
        alert_type = log.get("alert_type", "Normal Login")
        mapping    = STAGE_MAP.get(alert_type,
                                   ("Unknown", "T????", alert_type, 0))
        stage, tid, tname, stage_ord = mapping

        cur_dt    = _parse_ts(ts)
        tactic_ord = TACTIC_IDX.get(stage, 99)

        # Pivot / escalation detection
        is_escalation = tactic_ord > max_stage_seen
        is_pivot      = (is_escalation and max_stage_seen >= 0
                         and tactic_ord > max_stage_seen)
        max_stage_seen = max(max_stage_seen, tactic_ord)

        # Dwell time within this stage
        dwell_secs: Optional[int] = None
        if stage in stage_last_ts:
            dwell_secs = int((cur_dt - stage_last_ts[stage]).total_seconds())
        stage_last_ts[stage] = cur_dt

        rc = _risk_contribution(alert_type, int(log.get("failed_logins", 0)), is_pivot)

        entries.append(TimelineEntry(
            index           = idx,
            timestamp       = ts,
            timestamp_rel   = _rel_time(first_dt, cur_dt),
            event_id        = str(log.get("event_id", "?")),
            alert_type      = alert_type,
            source_ip       = log.get("source_ip",    "?"),
            failed_logins   = int(log.get("failed_logins", 0)),
            location        = log.get("location",     "Unknown"),
            device          = log.get("device",       "Unknown"),
            stage           = stage,
            technique_id    = tid,
            technique_name  = tname,
            stage_order     = stage_ord,
            is_pivot        = is_pivot,
            is_escalation   = is_escalation,
            is_anomaly      = alert_type not in ("Normal Login",),
            risk_contribution = rc,
            color           = STAGE_COLORS.get(stage, "#6b7280"),
            severity        = SEVERITY_FOR_STAGE.get(stage, "Low"),
            dwell_seconds   = dwell_secs,
            dwell_label     = _dwell_label(dwell_secs),
        ))

    # ── Metadata ──────────────────────────────────────────────────────────────
    duration_s  = int((last_dt - first_dt).total_seconds())
    stages_seen = list(dict.fromkeys(e.stage for e in entries))   # ordered, unique
    pivots      = [e for e in entries if e.is_pivot]
    escalations = [e for e in entries if e.is_escalation]

    # Attack progression (stage names in order of first appearance)
    progression = list(dict.fromkeys(e.stage for e in entries if e.stage != "Unknown"))

    # Chain completeness (out of 6 canonical stages)
    canonical_6 = {
        "Initial Access", "Execution", "Privilege Escalation",
        "Credential Access", "Lateral Movement", "Exfiltration"
    }
    covered     = canonical_6 & set(stages_seen)
    completeness = int(len(covered) / len(canonical_6) * 100)
    has_chain   = completeness >= 50

    meta = TimelineMeta(
        total_events       = len(entries),
        unique_stages      = stages_seen,
        stage_count        = len(set(stages_seen)),
        pivot_count        = len(pivots),
        escalation_count   = len(escalations),
        first_ts           = events[0][0],
        last_ts            = events[-1][0],
        duration_seconds   = duration_s,
        duration_label     = _duration_label(duration_s),
        attack_progression = progression,
        has_full_chain     = has_chain,
        completeness_pct   = completeness,
    )

    return TimelineResult(entries=entries, meta=meta)


def get_pivot_events(result: TimelineResult) -> list[TimelineEntry]:
    return [e for e in result.entries if e.is_pivot]


def get_stage_groups(result: TimelineResult) -> dict[str, list[TimelineEntry]]:
    """Group timeline entries by MITRE stage."""
    groups: dict[str, list[TimelineEntry]] = {}
    for e in result.entries:
        groups.setdefault(e.stage, []).append(e)
    return groups


def get_progression_summary(result: TimelineResult) -> str:
    """
    One-line human-readable progression:
    e.g. "Initial Access → Execution → Privilege Escalation (25m total)"
    """
    prog = result.meta.attack_progression
    if not prog:
        return "No attack progression detected."
    chain = " → ".join(prog)
    return f"{chain} ({result.meta.duration_label} total)"


if __name__ == "__main__":
    print("Timeline Engine — Self-Test\n" + "=" * 50)
    from datetime import timezone

    now = datetime.now(timezone.utc)
    test_logs = [
        {"timestamp": (now - timedelta(minutes=25)).isoformat(),
         "alert_type": "Brute Force",          "source_ip": "45.33.32.1",
         "failed_logins": 25, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=20)).isoformat(),
         "alert_type": "Brute Force",          "source_ip": "45.33.32.1",
         "failed_logins": 30, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=15)).isoformat(),
         "alert_type": "Normal Login",          "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "4624", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=10)).isoformat(),
         "alert_type": "Suspicious Activity",  "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "1",    "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=5)).isoformat(),
         "alert_type": "Privilege Escalation", "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "4672", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=2)).isoformat(),
         "alert_type": "Credential Dumping",   "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "10",   "location": "Russia", "device": "Linux"},
    ]

    result = build_timeline(test_logs)
    print(f"Progression: {get_progression_summary(result)}")
    print(f"Pivots: {result.meta.pivot_count} | "
          f"Stages: {result.meta.stage_count} | "
          f"Chain completeness: {result.meta.completeness_pct}%")
    print("\nTimeline:")
    for e in result.entries:
        pivot_str = " ◄ PIVOT" if e.is_pivot else ""
        print(f"  {e.timestamp_rel:>10} | {e.stage:25s} | "
              f"{e.technique_id:12s} | {e.alert_type}{pivot_str}")
