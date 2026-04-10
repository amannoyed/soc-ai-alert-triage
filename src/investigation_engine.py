"""
investigation_engine.py
════════════════════════
AI Investigation Engine

Synthesizes outputs from all detection layers into a structured
SOC analyst-style investigation report.

Inputs:
  - CorrelationResult    (attack chains, timeline)
  - DetectionResult(s)  (ML + anomaly + baseline)
  - UEBAResult(s)       (behavioral profiling)
  - IP threat intel     (AbuseIPDB score etc.)

Outputs:
  - attack_summary      (1–3 sentence overview)
  - reasoning_steps     (numbered analyst logic)
  - confidence          (0–100)
  - recommended_actions (prioritized response)
  - iocs                (extracted indicators)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class IOC:
    type:  str    # "ip" | "technique" | "behavior"
    value: str
    note:  str


@dataclass
class InvestigationReport:
    case_id:            str
    timestamp:          str
    attack_summary:     str
    attack_classification: str     # e.g. "Targeted Brute Force → Privilege Escalation"
    reasoning_steps:    list[str]
    confidence:         int        # 0–100
    severity:           str
    recommended_actions: list[str]
    iocs:               list[IOC]
    mitre_techniques:   list[str]
    affected_ips:       list[str]
    timeline_narrative: str        # prose walk-through of the attack

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def to_text(self) -> str:
        lines = [
            f"═══════════════════════════════════════════",
            f"SOC INVESTIGATION REPORT — {self.case_id}",
            f"═══════════════════════════════════════════",
            f"Timestamp : {self.timestamp}",
            f"Severity  : {self.severity}",
            f"Confidence: {self.confidence}%",
            f"",
            f"ATTACK CLASSIFICATION",
            f"  {self.attack_classification}",
            f"",
            f"SUMMARY",
            f"  {self.attack_summary}",
            f"",
            f"TIMELINE NARRATIVE",
            f"  {self.timeline_narrative}",
            f"",
            f"ANALYST REASONING",
        ]
        for i, step in enumerate(self.reasoning_steps, 1):
            lines.append(f"  {i}. {step}")
        lines += [
            f"",
            f"MITRE ATT&CK",
            f"  {', '.join(self.mitre_techniques) or 'None mapped'}",
            f"",
            f"INDICATORS OF COMPROMISE",
        ]
        for ioc in self.iocs:
            lines.append(f"  [{ioc.type.upper()}] {ioc.value} — {ioc.note}")
        lines += [
            f"",
            f"RECOMMENDED ACTIONS",
        ]
        for i, action in enumerate(self.recommended_actions, 1):
            lines.append(f"  {i}. {action}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION RULES
# ══════════════════════════════════════════════════════════════════════════════

def _classify_attack(alert_types: list[str],
                     has_chain:   bool,
                     confidence:  int) -> str:
    types_set = set(alert_types)

    if "Credential Dumping" in types_set and "Privilege Escalation" in types_set:
        return "Full Compromise — Credential Access + Privilege Escalation"

    if has_chain and confidence >= 80:
        if "Brute Force" in types_set and "Privilege Escalation" in types_set:
            return "Targeted Attack — Brute Force → Privilege Escalation"
        if "Malware Execution" in types_set:
            return "Malware Intrusion — Active Payload Execution"

    if "Credential Stuffing" in types_set:
        return "Credential Attack — Stuffing / Replay"

    if "Password Spray" in types_set:
        return "Password Spray — Low-and-Slow Authentication Attack"

    if types_set & {"Brute Force", "Suspicious Login"}:
        return "Authentication Attack — Brute Force / Suspicious Login"

    if "Suspicious Activity" in types_set:
        return "Suspicious Execution — Possible Post-Exploitation"

    return "Anomalous Activity — Classification Pending"


# ══════════════════════════════════════════════════════════════════════════════
# NARRATIVE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def _build_timeline_narrative(timeline_events: list) -> str:
    """
    Build a prose walk-through of the attack timeline.
    timeline_events: list of TimelineEvent dataclass instances.
    """
    if not timeline_events:
        return "No timeline events available."

    stages_seen = []
    for ev in timeline_events:
        stage = getattr(ev, "stage", "") or ""
        if stage and (not stages_seen or stages_seen[-1] != stage):
            stages_seen.append(stage)

    first = timeline_events[0]
    last  = timeline_events[-1]

    try:
        first_ts = first.timestamp[:19].replace("T", " ")
        last_ts  = last.timestamp[:19].replace("T", " ")
    except Exception:
        first_ts = last_ts = "unknown time"

    ips = list({getattr(e, "source_ip", "?") for e in timeline_events})
    ip_str = ips[0] if len(ips) == 1 else f"{len(ips)} source IPs"

    pivots = [e for e in timeline_events if getattr(e, "is_pivot", False)]

    lines = [f"Activity began at {first_ts} from {ip_str}."]

    stage_descriptions = {
        "Initial Access":       "Initial access was attempted via authentication attacks.",
        "Execution":            "Post-access, suspicious process execution was observed.",
        "Privilege Escalation": "The attacker escalated privileges on the target system.",
        "Credential Access":    "Credential harvesting activity was detected.",
        "Lateral Movement":     "Lateral movement indicators were observed.",
    }
    for stage in stages_seen:
        desc = stage_descriptions.get(stage)
        if desc:
            lines.append(desc)

    if pivots:
        pivot_types = [getattr(p, "alert_type", "?") for p in pivots]
        lines.append(
            f"Key escalation point(s) identified: {', '.join(pivot_types)}."
        )

    lines.append(f"Activity concluded (last observed) at {last_ts}.")

    return " ".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# REASONING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _build_reasoning(
    alert_types:     list[str],
    unique_ips:      list[str],
    ml_confidence:   float,
    anomaly_score:   float,
    baseline_score:  float,
    ueba_results:    list,
    ip_intel:        dict,
    chain_alerts:    list,
    burst_alerts:    list,
    final_score:     int,
) -> list[str]:
    steps = []

    # Step 1 — observed activity
    types_str = ", ".join(sorted(set(alert_types))) or "normal login"
    steps.append(
        f"Observed activity types: [{types_str}] from "
        f"{len(unique_ips)} unique IP(s): {', '.join(unique_ips[:5])}."
    )

    # Step 2 — ML assessment
    conf_pct = ml_confidence * 100
    if ml_confidence >= 0.8:
        steps.append(
            f"ML classifier assessed this as a threat with {conf_pct:.0f}% confidence. "
            f"Training patterns strongly match known attack signatures."
        )
    elif ml_confidence >= 0.5:
        steps.append(
            f"ML classifier flagged this as suspicious ({conf_pct:.0f}% threat probability). "
            f"Pattern partially matches known attack signatures."
        )
    else:
        steps.append(
            f"ML classifier shows low threat probability ({conf_pct:.0f}%). "
            f"Threat assessment driven primarily by rule-based and anomaly signals."
        )

    # Step 3 — Anomaly detection
    if anomaly_score >= 70:
        steps.append(
            f"Isolation Forest anomaly detector flagged this event as highly anomalous "
            f"(score {anomaly_score:.0f}/100). Behavioral pattern falls well outside "
            f"the normal distribution of training events."
        )
    elif anomaly_score >= 40:
        steps.append(
            f"Anomaly detection shows moderate deviation from baseline "
            f"(score {anomaly_score:.0f}/100). Activity is unusual but not extreme."
        )
    else:
        steps.append(
            f"Anomaly score is low ({anomaly_score:.0f}/100). Activity appears "
            f"within normal behavioral range per Isolation Forest."
        )

    # Step 4 — Statistical baseline
    if baseline_score >= 50:
        steps.append(
            f"Statistical baseline analysis shows significant deviation "
            f"(score {baseline_score:.0f}/100). Failed login count and/or "
            f"geographic origin exceed the 95th percentile of normal traffic."
        )
    elif baseline_score >= 20:
        steps.append(
            f"Baseline deviation score is {baseline_score:.0f}/100 — "
            f"activity is above normal thresholds in at least one dimension."
        )

    # Step 5 — UEBA
    ueba_spikes = [u for u in ueba_results
                   if getattr(u, "spike_detected", False)]
    ueba_new_loc = [u for u in ueba_results
                    if getattr(u, "new_location", False)]
    if ueba_spikes:
        ips_spiking = [u.ip for u in ueba_spikes]
        steps.append(
            f"UEBA analysis detected activity spikes for IP(s): "
            f"{', '.join(ips_spiking)}. Current attempt count is significantly "
            f"above their individual behavioral baseline."
        )
    if ueba_new_loc:
        ips_new = [u.ip for u in ueba_new_loc]
        steps.append(
            f"New geographic origin detected for IP(s) {', '.join(ips_new)}. "
            f"These IPs have not previously been seen from this location — "
            f"possible VPN pivot or compromised relay."
        )

    # Step 6 — Threat intel
    malicious_ips = [ip for ip, score in ip_intel.items() if score >= 75]
    suspicious_ips = [ip for ip, score in ip_intel.items() if 30 <= score < 75]
    if malicious_ips:
        steps.append(
            f"Threat intelligence confirms {len(malicious_ips)} IP(s) as known "
            f"malicious in AbuseIPDB: {', '.join(malicious_ips[:5])}. "
            f"These IPs have prior abuse reports."
        )
    elif suspicious_ips:
        steps.append(
            f"Threat intelligence flags {len(suspicious_ips)} IP(s) as suspicious: "
            f"{', '.join(suspicious_ips[:5])}."
        )

    # Step 7 — Correlation
    if chain_alerts:
        top = chain_alerts[0]
        steps.append(
            f"Correlation engine matched the event sequence to known attack pattern: "
            f"'{top.name}' (confidence {top.confidence}%). "
            f"MITRE techniques: {', '.join(top.mitre_techniques)}."
        )
    if burst_alerts:
        steps.append(
            f"Burst detection triggered: {burst_alerts[0].description}"
        )

    # Step 8 — Conclusion
    if final_score >= 80:
        steps.append(
            f"CONCLUSION: Combined evidence strongly indicates a real attack in progress. "
            f"Final risk score {final_score}/100. Immediate response is required."
        )
    elif final_score >= 60:
        steps.append(
            f"CONCLUSION: High likelihood of malicious activity (score {final_score}/100). "
            f"Escalation and investigation recommended within the hour."
        )
    elif final_score >= 35:
        steps.append(
            f"CONCLUSION: Suspicious activity warranting monitoring (score {final_score}/100). "
            f"No immediate action required but watchlist entry advised."
        )
    else:
        steps.append(
            f"CONCLUSION: Activity appears benign based on combined analysis "
            f"(score {final_score}/100). Log retained for audit."
        )

    return steps


# ══════════════════════════════════════════════════════════════════════════════
# IOC EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def _extract_iocs(
    unique_ips:   list[str],
    mitre_tags:   list[str],
    alert_types:  list[str],
    ip_intel:     dict,
) -> list[IOC]:
    iocs = []

    for ip in unique_ips:
        score = ip_intel.get(ip, 0)
        note  = (f"AbuseIPDB score {score}/100 — malicious" if score >= 75 else
                 f"AbuseIPDB score {score}/100 — suspicious" if score >= 30 else
                 "No known threat intel — suspicious by behavior")
        iocs.append(IOC(type="ip", value=ip, note=note))

    for technique in mitre_tags:
        iocs.append(IOC(
            type  = "technique",
            value = technique,
            note  = "MITRE ATT&CK technique observed in this event chain",
        ))

    behavior_map = {
        "Brute Force":          "High-volume authentication failure pattern",
        "Credential Stuffing":  "Credential replay using leaked password lists",
        "Malware Execution":    "Suspicious process or script executed",
        "Credential Dumping":   "Memory or file-based credential extraction",
        "Privilege Escalation": "Unauthorized privilege assignment detected",
    }
    for atype in set(alert_types):
        note = behavior_map.get(atype)
        if note:
            iocs.append(IOC(type="behavior", value=atype, note=note))

    return iocs


# ══════════════════════════════════════════════════════════════════════════════
# RECOMMENDED ACTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _recommend_actions(
    final_score:  int,
    alert_types:  list[str],
    unique_ips:   list[str],
    has_chain:    bool,
) -> list[str]:
    actions = []
    types_set = set(alert_types)

    if final_score >= 80:
        actions += [
            f"🔴 IMMEDIATE: Block source IP(s) at firewall — "
            f"{', '.join(unique_ips[:5])}",
            "🔴 IMMEDIATE: Isolate any endpoint that authenticated from these IPs",
            "🔴 IMMEDIATE: Reset credentials for any accounts accessed",
            "🔴 IMMEDIATE: Escalate to Tier 2 / Incident Response team",
            "📋 Open a P1 incident ticket with full log evidence",
            "🔒 Enable multi-factor authentication for affected accounts",
            "📁 Preserve all logs (do not rotate) for forensic analysis",
        ]
    elif final_score >= 60:
        actions += [
            f"🟠 HIGH: Add IP(s) to watchlist — {', '.join(unique_ips[:5])}",
            "🟠 HIGH: Review authentication logs for the last 24 hours",
            "🟠 HIGH: Alert asset owners and security team",
            "📋 Open a P2 incident ticket",
            "🔍 Check for lateral movement from involved endpoints",
        ]
    elif final_score >= 35:
        actions += [
            "🟡 MEDIUM: Add IP(s) to 30-day watchlist",
            "🔍 Review user activity for the past 4 hours",
            "📋 Log event for audit trail — no immediate action required",
            "⚙️ Consider rate-limiting authentication from flagged IPs",
        ]
    else:
        actions += [
            "🟢 LOW: No immediate action required",
            "📋 Log event for routine audit",
        ]

    # Attack-type-specific actions
    if "Credential Dumping" in types_set:
        actions.append("🔴 CRITICAL: Assume all credentials on affected systems are compromised — rotate immediately")
    if "Privilege Escalation" in types_set:
        actions.append("🔴 HIGH: Review and revoke suspicious privilege assignments")
    if "Malware Execution" in types_set:
        actions.append("🔴 HIGH: Run endpoint AV/EDR scan on affected systems")
    if has_chain:
        actions.append("📊 Perform full kill-chain analysis and document for lessons-learned")

    return actions


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

import uuid


def investigate(
    correlation_result,               # CorrelationResult
    detection_results:  list,         # list[DetectionResult]
    ueba_results:       list,         # list[UEBAResult]
    ip_intel:           dict,         # {ip_str: abuse_score_int}
    final_score:        int,
    severity:           str,
) -> InvestigationReport:
    """
    Build a full SOC investigation report by synthesizing all detection outputs.

    Parameters
    ----------
    correlation_result : CorrelationResult
    detection_results  : list of DetectionResult (one per analyzed event)
    ueba_results       : list of UEBAResult (one per unique IP)
    ip_intel           : dict mapping IP → AbuseIPDB score
    final_score        : int 0–100, the pipeline's final fused risk score
    severity           : str severity label

    Returns
    -------
    InvestigationReport
    """
    case_id = f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    ts      = datetime.now(timezone.utc).isoformat()

    # Collect basic facts
    alert_types = [e.alert_type for e in correlation_result.timeline]
    unique_ips  = list({e.source_ip for e in correlation_result.timeline})

    chain_alerts = [a for a in correlation_result.alerts if a.attack_type == "chain"]
    burst_alerts = [a for a in correlation_result.alerts if a.attack_type == "burst"]

    all_mitre = []
    for a in correlation_result.alerts:
        all_mitre.extend(a.mitre_techniques)
    all_mitre = list(dict.fromkeys(all_mitre))  # dedupe, preserve order

    # ML / anomaly averages
    ml_conf_avg  = (sum(d.ml_confidence  for d in detection_results) /
                    max(len(detection_results), 1))
    anom_avg     = (sum(d.anomaly_score  for d in detection_results) /
                    max(len(detection_results), 1))
    base_avg     = (sum(d.baseline_score for d in detection_results) /
                    max(len(detection_results), 1))

    # Build components
    classification     = _classify_attack(alert_types, bool(chain_alerts),
                                          correlation_result.attack_confidence)
    reasoning          = _build_reasoning(
        alert_types, unique_ips, ml_conf_avg, anom_avg, base_avg,
        ueba_results, ip_intel, chain_alerts, burst_alerts, final_score,
    )
    timeline_narrative = _build_timeline_narrative(correlation_result.timeline)
    iocs               = _extract_iocs(unique_ips, all_mitre, alert_types, ip_intel)
    actions            = _recommend_actions(final_score, alert_types,
                                            unique_ips, bool(chain_alerts))

    # Attack summary (3 sentences max)
    summary = _build_attack_summary(
        classification, correlation_result, final_score, unique_ips, alert_types
    )

    return InvestigationReport(
        case_id                = case_id,
        timestamp              = ts,
        attack_summary         = summary,
        attack_classification  = classification,
        reasoning_steps        = reasoning,
        confidence             = correlation_result.attack_confidence or int(ml_conf_avg * 100),
        severity               = severity,
        recommended_actions    = actions,
        iocs                   = iocs,
        mitre_techniques       = all_mitre,
        affected_ips           = unique_ips,
        timeline_narrative     = timeline_narrative,
    )


def _build_attack_summary(
    classification: str,
    corr,
    final_score:    int,
    unique_ips:     list[str],
    alert_types:    list[str],
) -> str:
    type_counts: dict[str, int] = {}
    for t in alert_types:
        type_counts[t] = type_counts.get(t, 0) + 1

    dominant = max(type_counts, key=type_counts.get) if type_counts else "Unknown"
    ip_str   = unique_ips[0] if len(unique_ips) == 1 else f"{len(unique_ips)} source IPs"

    attack_desc = {
        "Brute Force":          f"brute-force authentication attacks from {ip_str}",
        "Credential Stuffing":  f"credential stuffing from {ip_str} using leaked passwords",
        "Password Spray":       f"low-rate password spray from {ip_str}",
        "Malware Execution":    f"malware execution following initial access from {ip_str}",
        "Credential Dumping":   f"credential harvesting activity from {ip_str}",
        "Privilege Escalation": f"privilege escalation following authentication from {ip_str}",
    }.get(dominant, f"suspicious activity from {ip_str}")

    sentence1 = f"This appears to be {attack_desc}."

    chain = [a for a in corr.alerts if a.attack_type == "chain"]
    if chain:
        sentence2 = (
            f"Correlation analysis matched a known attack chain: '{chain[0].name}' "
            f"with {chain[0].confidence}% confidence."
        )
    elif corr.alerts:
        sentence2 = (
            f"Correlation engine identified {len(corr.alerts)} pattern(s) "
            f"across {corr.total_events} events."
        )
    else:
        sentence2 = f"No specific attack chain was matched but behavioral signals are elevated."

    urgency = ("Immediate response required." if final_score >= 80 else
               "Escalation recommended." if final_score >= 60 else
               "Monitoring advised.")
    sentence3 = f"Final risk score: {final_score}/100 — {urgency}"

    return f"{sentence1} {sentence2} {sentence3}"


if __name__ == "__main__":
    print("Investigation Engine — Import test OK")
    print("Use investigate() with full pipeline outputs.")
