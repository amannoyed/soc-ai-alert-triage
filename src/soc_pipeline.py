"""
soc_pipeline.py
═══════════════
SOC Detection Pipeline — Master Orchestrator

Flow:
  Logs → Parse → UEBA → Correlation → Detection → Threat Intel
       → Scoring → Investigation → Timeline → PipelineResult

All modules are called once, outputs are passed cleanly between stages.
No duplicate logic — each module owns its responsibility.
"""

import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ── Module imports ─────────────────────────────────────────────────────────────
from log_parser          import parse_evtx
from detection_engine    import analyze, analyze_batch, DetectionResult
from ueba_engine         import analyze_from_log, UEBAResult, persist as ueba_persist
from correlation_engine  import correlate_events, CorrelationResult
from scoring_engine      import compute_score_from_batch, ScoringResult, ScoringConfig
from investigation_engine import investigate, InvestigationReport
from timeline_engine     import build_timeline, TimelineResult, get_progression_summary
from predict             import check_ip_reputation, map_mitre, ATTACK_RISK


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PipelineResult:
    # Raw
    raw_log_count:       int
    parsed_events:       list[dict]

    # Stage outputs
    detection_results:   list            # list[DetectionResult]
    ueba_results:        list            # list[UEBAResult]
    correlation:         object          # CorrelationResult
    scoring:             object          # ScoringResult
    investigation:       object          # InvestigationReport
    timeline:            object          # TimelineResult

    # Aggregated intel
    ip_intel:            dict            # {ip: (status_str, score)}
    mitre_techniques:    list[str]

    # Top-level summary
    final_score:         int
    severity:            str
    is_threat:           bool
    threat_ips:          list[str]
    unique_ips:          list[str]
    alert_type_counts:   dict[str, int]
    pipeline_duration_ms: int
    timestamp:           str

    def to_summary_dict(self) -> dict:
        """Lightweight dict for API/logging (no nested objects)."""
        return {
            "final_score":        self.final_score,
            "severity":           self.severity,
            "is_threat":          self.is_threat,
            "attack_summary":     self.investigation.attack_summary,
            "classification":     self.investigation.attack_classification,
            "confidence":         self.investigation.confidence,
            "unique_ips":         self.unique_ips,
            "threat_ips":         self.threat_ips,
            "mitre_techniques":   self.mitre_techniques,
            "event_count":        self.raw_log_count,
            "timeline_duration":  getattr(self.timeline.meta, "duration_label", ""),
            "attack_progression": getattr(self.timeline.meta, "attack_progression", []),
            "timestamp":          self.timestamp,
        }


# ══════════════════════════════════════════════════════════════════════════════
# IP INTEL HELPER (avoids calling API per event — deduplicated)
# ══════════════════════════════════════════════════════════════════════════════

def _batch_ip_intel(ips: list[str]) -> dict:
    """
    Returns {ip: (status_str, abuse_score)} for each unique IP.
    Skips private/loopback IPs.
    """
    results = {}
    private_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.2", "127.", "0.")
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        if any(ip.startswith(p) for p in private_prefixes):
            results[ip] = ("🟢 Internal IP", 0)
        else:
            try:
                status, score = check_ip_reputation(ip)
                results[ip] = (status, score)
            except Exception:
                results[ip] = ("⚠️ Lookup failed", 0)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# EVENT PREP — convert log dicts to detection-engine format
# ══════════════════════════════════════════════════════════════════════════════

def _log_to_detection_input(log: dict) -> dict:
    """Convert a parsed log dict into one-hot encoded detection_engine input."""
    alert_type = log.get("alert_type", "Normal Login")
    location   = log.get("location",   "Unknown")
    device     = log.get("device",     "Unknown")

    data = {"failed_logins": int(log.get("failed_logins", 0))}

    # One-hot alert type
    for at in list(ATTACK_RISK.keys()) + ["Normal Login"]:
        data[f"alert_type_{at}"] = 1 if alert_type == at else 0

    # One-hot location
    for loc in ("India", "US", "UK", "Germany", "Brazil",
                "Russia", "China", "North Korea"):
        data[f"location_{loc}"] = 1 if location == loc else 0

    # One-hot device
    for dev in ("Windows", "Linux", "MacOS", "Android", "iOS"):
        data[f"device_{dev}"] = 1 if device == dev else 0

    return data


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def run_pipeline(
    evtx_path:    Optional[str] = None,
    raw_logs:     Optional[list[dict]] = None,
    scoring_config: Optional[ScoringConfig] = None,
) -> PipelineResult:
    """
    Run the full SOC detection pipeline.

    Parameters
    ----------
    evtx_path     : path to a .evtx file (mutually exclusive with raw_logs)
    raw_logs      : pre-parsed list of log dicts
    scoring_config: optional custom ScoringConfig

    Returns
    -------
    PipelineResult
    """
    start = datetime.now(timezone.utc)

    # ── Stage 0: Parse ────────────────────────────────────────────────────────
    if raw_logs is None and evtx_path:
        logs = parse_evtx(evtx_path)
    elif raw_logs is not None:
        logs = raw_logs
    else:
        logs = []

    if not logs:
        return _empty_result()

    # ── Stage 1: UEBA ─────────────────────────────────────────────────────────
    ueba_results: list[UEBAResult] = []
    ueba_by_ip: dict[str, UEBAResult] = {}

    for log in logs:
        result = analyze_from_log(log)
        ueba_results.append(result)
        # Keep worst result per IP
        ip = log.get("source_ip", "0.0.0.0")
        if ip not in ueba_by_ip or result.anomaly_score > ueba_by_ip[ip].anomaly_score:
            ueba_by_ip[ip] = result

    ueba_persist()

    # ── Stage 2: Correlation ──────────────────────────────────────────────────
    correlation: CorrelationResult = correlate_events(logs)

    # ── Stage 3: Detection (per-event) ────────────────────────────────────────
    detection_inputs  = [_log_to_detection_input(log) for log in logs]
    detection_results: list[DetectionResult] = analyze_batch(detection_inputs)

    # ── Stage 4: Threat Intel (deduplicated) ──────────────────────────────────
    all_ips    = [log.get("source_ip", "0.0.0.0") for log in logs]
    unique_ips = list(dict.fromkeys(all_ips))
    ip_intel   = _batch_ip_intel(unique_ips)

    # Map: ip → abuse score (int)
    ip_scores  = {ip: score for ip, (_, score) in ip_intel.items()}
    max_intel_score = max(ip_scores.values(), default=0)

    # ── Stage 5: Scoring ──────────────────────────────────────────────────────
    scoring: ScoringResult = compute_score_from_batch(
        detection_results  = detection_results,
        ueba_results       = list(ueba_by_ip.values()),
        correlation_result = correlation,
        ip_abuse_scores    = ip_scores,
        config             = scoring_config,
    )

    # ── Stage 6: Investigation ────────────────────────────────────────────────
    investigation: InvestigationReport = investigate(
        correlation_result = correlation,
        detection_results  = detection_results,
        ueba_results       = list(ueba_by_ip.values()),
        ip_intel           = ip_scores,
        final_score        = scoring.final_score,
        severity           = scoring.severity,
    )

    # ── Stage 7: Timeline ─────────────────────────────────────────────────────
    timeline: TimelineResult = build_timeline(logs)

    # ── Aggregated metadata ───────────────────────────────────────────────────
    all_mitre: list[str] = []
    for a in correlation.alerts:
        all_mitre.extend(a.mitre_techniques)
    all_mitre = list(dict.fromkeys(all_mitre))

    alert_type_counts: dict[str, int] = {}
    for log in logs:
        at = log.get("alert_type", "Normal Login")
        alert_type_counts[at] = alert_type_counts.get(at, 0) + 1

    threat_ips = [
        ip for ip, score in ip_scores.items() if score >= 30
    ] + [
        r.ip for r in ueba_by_ip.values() if r.anomaly_score >= 50
    ]
    threat_ips = list(dict.fromkeys(threat_ips))

    end = datetime.now(timezone.utc)
    duration_ms = int((end - start).total_seconds() * 1000)

    return PipelineResult(
        raw_log_count       = len(logs),
        parsed_events       = logs,
        detection_results   = detection_results,
        ueba_results        = list(ueba_by_ip.values()),
        correlation         = correlation,
        scoring             = scoring,
        investigation       = investigation,
        timeline            = timeline,
        ip_intel            = ip_intel,
        mitre_techniques    = all_mitre,
        final_score         = scoring.final_score,
        severity            = scoring.severity,
        is_threat           = scoring.final_score >= 35,
        threat_ips          = threat_ips,
        unique_ips          = unique_ips,
        alert_type_counts   = alert_type_counts,
        pipeline_duration_ms = duration_ms,
        timestamp           = start.isoformat(),
    )


def _empty_result() -> PipelineResult:
    from correlation_engine import CorrelationResult
    from timeline_engine    import TimelineResult, TimelineMeta

    empty_corr = CorrelationResult(
        alerts=[], timeline=[], attack_confidence=0,
        highest_severity="Low", total_events=0, unique_ips=0,
        attack_summary="No events.", windows_analyzed={},
    )
    empty_tm = TimelineResult(
        entries=[],
        meta=TimelineMeta(0, [], 0, 0, 0, "", "", 0, "0s", [], False, 0),
    )
    from scoring_engine import ScoringResult
    empty_score = ScoringResult(0, "🟢 Low", "Very Low", 0, [], [],
                                "No events.", datetime.now(timezone.utc).isoformat())
    from investigation_engine import InvestigationReport
    empty_inv = InvestigationReport(
        case_id="SOC-EMPTY", timestamp=datetime.now(timezone.utc).isoformat(),
        attack_summary="No events to analyze.",
        attack_classification="None",
        reasoning_steps=[], confidence=0, severity="🟢 Low",
        recommended_actions=[], iocs=[], mitre_techniques=[],
        affected_ips=[], timeline_narrative="No events.",
    )

    return PipelineResult(
        raw_log_count=0, parsed_events=[], detection_results=[],
        ueba_results=[], correlation=empty_corr, scoring=empty_score,
        investigation=empty_inv, timeline=empty_tm, ip_intel={},
        mitre_techniques=[], final_score=0, severity="🟢 Low",
        is_threat=False, threat_ips=[], unique_ips=[],
        alert_type_counts={}, pipeline_duration_ms=0,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE — run from log list (no file needed)
# ══════════════════════════════════════════════════════════════════════════════

def run_from_logs(logs: list[dict],
                  config: Optional[ScoringConfig] = None) -> PipelineResult:
    """Shorthand: run pipeline with pre-parsed log list."""
    return run_pipeline(raw_logs=logs, scoring_config=config)


def run_from_evtx(path: str,
                  config: Optional[ScoringConfig] = None) -> PipelineResult:
    """Shorthand: run pipeline from EVTX file path."""
    return run_pipeline(evtx_path=path, scoring_config=config)


if __name__ == "__main__":
    print("SOC Pipeline — Self-Test\n" + "=" * 50)
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    test_logs = [
        {"timestamp": (now - timedelta(minutes=20)).isoformat(),
         "alert_type": "Brute Force",          "source_ip": "45.33.32.1",
         "failed_logins": 25, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=15)).isoformat(),
         "alert_type": "Brute Force",          "source_ip": "45.33.32.1",
         "failed_logins": 30, "event_id": "4625", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=10)).isoformat(),
         "alert_type": "Normal Login",          "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "4624", "location": "Russia", "device": "Linux"},
        {"timestamp": (now - timedelta(minutes=5)).isoformat(),
         "alert_type": "Privilege Escalation", "source_ip": "45.33.32.1",
         "failed_logins": 0,  "event_id": "4672", "location": "Russia", "device": "Linux"},
    ]

    result = run_from_logs(test_logs)
    print(f"Score:    {result.final_score}/100")
    print(f"Severity: {result.severity}")
    print(f"Summary:  {result.investigation.attack_summary}")
    print(f"Timeline: {get_progression_summary(result.timeline)}")
    print(f"Duration: {result.pipeline_duration_ms}ms")
