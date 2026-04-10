"""
correlation_engine.py
═════════════════════
Time-Aware Correlation Engine

Detects:
  - Burst attacks       (many events in short window)
  - Slow brute force    (sustained low-rate attempts)
  - Multi-stage chains  (MITRE-mapped event sequences)
  - Distributed attacks (same pattern, multiple IPs)

All detection uses sliding time windows:
  - 2 min  → burst detection
  - 10 min → slow brute force
  - 30 min → full attack chain
"""

import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Attack chain sequences (Event ID order matters) ───────────────────────────
# Each sequence is a list of alert_type patterns that form a known chain.
KNOWN_CHAINS = [
    {
        "name":        "Brute Force → Successful Login → Privilege Escalation",
        "sequence":    ["Brute Force", "Normal Login", "Privilege Escalation"],
        "severity":    "Critical",
        "confidence":  95,
        "mitre":       ["T1110", "T1078", "T1068"],
        "description": "Classic attack chain: attacker brute-forced credentials, "
                       "gained access, then escalated privileges.",
    },
    {
        "name":        "Credential Stuffing → Successful Login",
        "sequence":    ["Credential Stuffing", "Normal Login"],
        "severity":    "High",
        "confidence":  85,
        "mitre":       ["T1110.004", "T1078"],
        "description": "Credential stuffing with at least one successful authentication.",
    },
    {
        "name":        "Password Spray → Suspicious Activity",
        "sequence":    ["Password Spray", "Suspicious Activity"],
        "severity":    "High",
        "confidence":  80,
        "mitre":       ["T1110.003", "T1059"],
        "description": "Password spray followed by suspicious process execution — "
                       "possible foothold established.",
    },
    {
        "name":        "Initial Access → Execution → Credential Dump",
        "sequence":    ["Brute Force", "Malware Execution", "Credential Dumping"],
        "severity":    "Critical",
        "confidence":  98,
        "mitre":       ["T1110", "T1059.001", "T1003"],
        "description": "Full attack chain: brute force, malware dropped, "
                       "credentials harvested from memory.",
    },
    {
        "name":        "Suspicious Login → Privilege Escalation",
        "sequence":    ["Suspicious Login", "Privilege Escalation"],
        "severity":    "High",
        "confidence":  82,
        "mitre":       ["T1078", "T1068"],
        "description": "Suspicious authentication followed by privilege escalation.",
    },
]

# Windows (seconds)
WINDOW_BURST  = 120    #  2 min
WINDOW_SLOW   = 600    # 10 min
WINDOW_CHAIN  = 1800   # 30 min

BURST_THRESHOLD      = 5    # events in 2 min → burst
SLOW_BF_THRESHOLD    = 8    # failed events in 10 min → slow brute force
SLOW_BF_MIN_FAILURES = 3    # min unique timestamps

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TimelineEvent:
    timestamp:     str
    event_id:      str
    alert_type:    str
    source_ip:     str
    failed_logins: int
    location:      str = "Unknown"
    device:        str = "Unknown"
    stage:         str = ""         # MITRE stage (filled by correlator)
    is_pivot:      bool = False     # marks escalation pivot points
    is_escalation: bool = False


@dataclass
class CorrelatedAlert:
    name:             str
    severity:         str
    confidence:       int           # 0–100
    description:      str
    mitre_techniques: list[str]
    event_count:      int
    window_seconds:   int
    first_event_ts:   str
    last_event_ts:    str
    source_ips:       list[str]
    attack_type:      str           # "burst" | "slow_bf" | "chain" | "distributed"


@dataclass
class CorrelationResult:
    alerts:              list[CorrelatedAlert]
    timeline:            list[TimelineEvent]
    attack_confidence:   int         # 0–100, overall campaign confidence
    highest_severity:    str
    total_events:        int
    unique_ips:          int
    attack_summary:      str
    windows_analyzed:    dict        # {"burst": n, "slow": n, "chain": n}

    def to_dict(self) -> dict:
        return {
            "alerts":            [asdict(a) for a in self.alerts],
            "timeline":          [asdict(t) for t in self.timeline],
            "attack_confidence": self.attack_confidence,
            "highest_severity":  self.highest_severity,
            "total_events":      self.total_events,
            "unique_ips":        self.unique_ips,
            "attack_summary":    self.attack_summary,
            "windows_analyzed":  self.windows_analyzed,
        }


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


def _window_filter(events: list[TimelineEvent],
                   anchor_ts: datetime,
                   seconds: int) -> list[TimelineEvent]:
    cutoff = anchor_ts - timedelta(seconds=seconds)
    return [e for e in events if _parse_ts(e.timestamp) >= cutoff]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


MITRE_STAGE_MAP = {
    "Brute Force":          "Initial Access",
    "Credential Stuffing":  "Initial Access",
    "Password Spray":       "Initial Access",
    "Suspicious Login":     "Initial Access",
    "Normal Login":         "Initial Access",
    "Suspicious Activity":  "Execution",
    "Malware Execution":    "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Credential Dumping":   "Credential Access",
}


def _assign_stage(alert_type: str) -> str:
    return MITRE_STAGE_MAP.get(alert_type, "Unknown")


def _mark_pivots(timeline: list[TimelineEvent]) -> list[TimelineEvent]:
    """
    Mark events where the MITRE stage advances (escalation pivots).
    """
    stage_order = [
        "Initial Access", "Execution",
        "Privilege Escalation", "Credential Access",
    ]
    prev_idx = -1
    for ev in timeline:
        ev.stage = _assign_stage(ev.alert_type)
        try:
            idx = stage_order.index(ev.stage)
        except ValueError:
            idx = -1
        if idx > prev_idx and prev_idx >= 0:
            ev.is_pivot      = True
            ev.is_escalation = True
        prev_idx = max(prev_idx, idx)
    return timeline


# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS
# ══════════════════════════════════════════════════════════════════════════════

def _detect_burst(events: list[TimelineEvent]) -> list[CorrelatedAlert]:
    alerts = []
    if not events:
        return alerts

    anchor = _parse_ts(events[-1].timestamp)
    window = _window_filter(events, anchor, WINDOW_BURST)

    # Group by IP
    by_ip: dict[str, list[TimelineEvent]] = defaultdict(list)
    for e in window:
        by_ip[e.source_ip].append(e)

    for ip, evs in by_ip.items():
        if len(evs) >= BURST_THRESHOLD:
            alerts.append(CorrelatedAlert(
                name             = "Burst Attack Detected",
                severity         = "High",
                confidence       = min(95, 60 + len(evs) * 5),
                description      = (
                    f"{len(evs)} events from {ip} in under "
                    f"{WINDOW_BURST // 60} minutes — likely automated attack tool."
                ),
                mitre_techniques = ["T1110", "T1078"],
                event_count      = len(evs),
                window_seconds   = WINDOW_BURST,
                first_event_ts   = evs[0].timestamp,
                last_event_ts    = evs[-1].timestamp,
                source_ips       = [ip],
                attack_type      = "burst",
            ))

    # Also check: many IPs hitting in short window (distributed burst)
    all_ips = list(by_ip.keys())
    total   = len(window)
    if len(all_ips) >= 3 and total >= BURST_THRESHOLD * 2:
        alerts.append(CorrelatedAlert(
            name             = "Distributed Burst Attack",
            severity         = "Critical",
            confidence       = 88,
            description      = (
                f"{total} events from {len(all_ips)} distinct IPs in "
                f"{WINDOW_BURST // 60} min — coordinated attack."
            ),
            mitre_techniques = ["T1110", "T1078", "T1199"],
            event_count      = total,
            window_seconds   = WINDOW_BURST,
            first_event_ts   = window[0].timestamp,
            last_event_ts    = window[-1].timestamp,
            source_ips       = all_ips,
            attack_type      = "distributed",
        ))

    return alerts


def _detect_slow_brute_force(events: list[TimelineEvent]) -> list[CorrelatedAlert]:
    alerts = []
    if not events:
        return alerts

    anchor = _parse_ts(events[-1].timestamp)
    window = _window_filter(events, anchor, WINDOW_SLOW)

    by_ip: dict[str, list[TimelineEvent]] = defaultdict(list)
    for e in window:
        if e.alert_type in ("Brute Force", "Credential Stuffing",
                            "Password Spray", "Suspicious Login"):
            by_ip[e.source_ip].append(e)

    for ip, evs in by_ip.items():
        timestamps = sorted(set(e.timestamp for e in evs))
        if (len(evs) >= SLOW_BF_THRESHOLD
                and len(timestamps) >= SLOW_BF_MIN_FAILURES):
            # Estimate rate
            first = _parse_ts(timestamps[0])
            last  = _parse_ts(timestamps[-1])
            span  = max((last - first).total_seconds(), 1)
            rate  = len(evs) / (span / 60)  # events per minute

            alerts.append(CorrelatedAlert(
                name             = "Slow Brute Force Attack",
                severity         = "High",
                confidence       = min(92, 55 + len(evs) * 4),
                description      = (
                    f"IP {ip} made {len(evs)} authentication attempts over "
                    f"{span/60:.1f} min at {rate:.1f} attempts/min — "
                    f"slow credential attack to evade rate limiting."
                ),
                mitre_techniques = ["T1110", "T1110.001"],
                event_count      = len(evs),
                window_seconds   = WINDOW_SLOW,
                first_event_ts   = timestamps[0],
                last_event_ts    = timestamps[-1],
                source_ips       = [ip],
                attack_type      = "slow_bf",
            ))

    return alerts


def _detect_chains(events: list[TimelineEvent]) -> list[CorrelatedAlert]:
    alerts = []
    if not events:
        return alerts

    anchor = _parse_ts(events[-1].timestamp)
    window = _window_filter(events, anchor, WINDOW_CHAIN)

    # Build ordered alert-type sequence (de-duplicated consecutive)
    sequence = []
    for e in window:
        if not sequence or sequence[-1] != e.alert_type:
            sequence.append(e.alert_type)

    for chain in KNOWN_CHAINS:
        pattern = chain["sequence"]
        # Check if pattern appears as a subsequence
        idx, matched = 0, 0
        for atype in sequence:
            if matched < len(pattern) and atype == pattern[matched]:
                matched += 1
            if matched == len(pattern):
                idx += 1
                matched = 0

        if idx >= 1:
            unique_ips = list({e.source_ip for e in window})
            alerts.append(CorrelatedAlert(
                name             = chain["name"],
                severity         = chain["severity"],
                confidence       = chain["confidence"],
                description      = chain["description"],
                mitre_techniques = chain["mitre"],
                event_count      = len(window),
                window_seconds   = WINDOW_CHAIN,
                first_event_ts   = window[0].timestamp,
                last_event_ts    = window[-1].timestamp,
                source_ips       = unique_ips,
                attack_type      = "chain",
            ))

    return alerts


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════

def correlate_events(raw_logs: list[dict]) -> CorrelationResult:
    """
    Main entry point.

    Parameters
    ----------
    raw_logs : list[dict]
        Each dict must have: timestamp (ISO), alert_type, source_ip,
        failed_logins, event_id (optional), location, device.

    Returns
    -------
    CorrelationResult
    """
    if not raw_logs:
        return CorrelationResult(
            alerts=[], timeline=[], attack_confidence=0,
            highest_severity="Low", total_events=0, unique_ips=0,
            attack_summary="No events to correlate.",
            windows_analyzed={"burst": 0, "slow": 0, "chain": 0},
        )

    # Build timeline events, assign timestamps if missing
    now = datetime.now(timezone.utc)
    timeline: list[TimelineEvent] = []
    for i, log in enumerate(raw_logs):
        ts = log.get("timestamp") or (now - timedelta(seconds=(len(raw_logs)-i)*10)).isoformat()
        timeline.append(TimelineEvent(
            timestamp     = ts,
            event_id      = str(log.get("event_id", "?")),
            alert_type    = log.get("alert_type", "Normal Login"),
            source_ip     = log.get("source_ip", "0.0.0.0"),
            failed_logins = int(log.get("failed_logins", 0)),
            location      = log.get("location", "Unknown"),
            device        = log.get("device", "Unknown"),
        ))

    # Sort by time
    timeline.sort(key=lambda e: _parse_ts(e.timestamp))

    # Assign MITRE stages + pivot markers
    timeline = _mark_pivots(timeline)

    # Run detectors
    burst_alerts  = _detect_burst(timeline)
    slow_alerts   = _detect_slow_brute_force(timeline)
    chain_alerts  = _detect_chains(timeline)

    all_alerts = burst_alerts + slow_alerts + chain_alerts

    # Deduplicate by name (keep highest confidence)
    seen: dict[str, CorrelatedAlert] = {}
    for a in all_alerts:
        if a.name not in seen or a.confidence > seen[a.name].confidence:
            seen[a.name] = a
    all_alerts = sorted(seen.values(),
                        key=lambda a: SEVERITY_ORDER.get(a.severity, 0),
                        reverse=True)

    # Overall stats
    unique_ips = list({e.source_ip for e in timeline})
    sev_vals   = [SEVERITY_ORDER.get(a.severity, 0) for a in all_alerts]
    max_sev    = max(sev_vals, default=0)
    sev_labels = {v: k for k, v in SEVERITY_ORDER.items()}
    highest    = sev_labels.get(max_sev, "Low")

    # Overall attack confidence
    if chain_alerts:
        conf = max(a.confidence for a in chain_alerts)
    elif burst_alerts or slow_alerts:
        conf = max((a.confidence for a in (burst_alerts + slow_alerts)), default=0)
    else:
        conf = 0

    # Summary text
    summary = _build_summary(all_alerts, timeline, unique_ips, conf)

    return CorrelationResult(
        alerts            = all_alerts,
        timeline          = timeline,
        attack_confidence = conf,
        highest_severity  = highest,
        total_events      = len(timeline),
        unique_ips        = len(unique_ips),
        attack_summary    = summary,
        windows_analyzed  = {
            "burst": len(burst_alerts),
            "slow":  len(slow_alerts),
            "chain": len(chain_alerts),
        },
    )


def _build_summary(alerts: list[CorrelatedAlert],
                   timeline: list[TimelineEvent],
                   unique_ips: list[str],
                   confidence: int) -> str:
    if not alerts:
        types = list({e.alert_type for e in timeline})
        return (
            f"Analyzed {len(timeline)} events from {len(unique_ips)} IP(s). "
            f"Event types: {', '.join(types)}. No attack patterns correlated."
        )

    top = alerts[0]
    lines = [
        f"{len(alerts)} correlated alert(s) from {len(unique_ips)} unique IP(s). "
        f"Primary: '{top.name}' (confidence {top.confidence}%). "
        f"Overall campaign confidence: {confidence}%."
    ]

    chain = [a for a in alerts if a.attack_type == "chain"]
    if chain:
        lines.append(f"Attack chain detected: {chain[0].name}. "
                     f"MITRE: {', '.join(chain[0].mitre_techniques)}.")

    return " ".join(lines)


if __name__ == "__main__":
    print("Correlation Engine — Self-Test\n" + "=" * 50)
    from datetime import timezone

    now = datetime.now(timezone.utc)

    logs = [
        {"timestamp": (now - timedelta(minutes=20)).isoformat(),
         "alert_type": "Brute Force", "source_ip": "45.33.32.1",
         "failed_logins": 25, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=18)).isoformat(),
         "alert_type": "Brute Force", "source_ip": "45.33.32.1",
         "failed_logins": 30, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=15)).isoformat(),
         "alert_type": "Normal Login", "source_ip": "45.33.32.1",
         "failed_logins": 0, "event_id": "4624", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=10)).isoformat(),
         "alert_type": "Privilege Escalation", "source_ip": "45.33.32.1",
         "failed_logins": 0, "event_id": "4672", "location": "Russia", "device": "Linux"},
    ]

    result = correlate_events(logs)
    print(f"Confidence: {result.attack_confidence}%")
    print(f"Severity:   {result.highest_severity}")
    print(f"Summary:    {result.attack_summary}")
    print(f"\nAlerts ({len(result.alerts)}):")
    for a in result.alerts:
        print(f"  [{a.severity}] {a.name} — {a.description}")
    print(f"\nTimeline ({len(result.timeline)} events):")
    for t in result.timeline:
        pivot = " ← PIVOT" if t.is_pivot else ""
        print(f"  {t.timestamp[:19]} | {t.stage:25s} | {t.alert_type}{pivot}")
