"""
detection_engine.py
═══════════════════
Hybrid SOC Detection Engine — honest edition.

Per-event risk from three independent layers:
  Layer 1 — Rules engine (transparent heuristics on observable signals)  40%
  Layer 2 — Isolation Forest anomaly vs. benign baseline (real ML)       30%
  Layer 3 — Statistical baseline deviation (z-score / p95 / p99)         30%

Input contract: RAW parsed log dicts —
  {event_id, timestamp, alert_type, failed_logins, source_ip,
   location, device, process_risk}

What changed vs. the old engine:
  - DELETED the GradientBoosting classifier. It was trained on labels that
    were a deterministic function of alert_type, so it "detected" whatever
    the input already said. Decorative, not detection.
  - DELETED all one-hot alert_type features (the leakage vector).
  - DELETED label-derived "threat rates" from the statistical baseline.
  - IsolationForest contamination 0.40 → 0.05, trained on BENIGN data only.
  - No training at import time — models load lazily on first analyze().
"""

import os
import sys
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from features import extract_features, EVENT_RISK
import anomaly_model

_BASE          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR     = os.path.join(_BASE, "model")
_BASELINE_PATH = os.path.join(_MODEL_DIR, "baseline.json")

WEIGHTS = {"rules": 0.40, "anomaly": 0.30, "baseline": 0.30}

# Documented heuristic: regions most associated with opportunistic attacks.
HIGH_RISK_LOCATIONS = {"Russia", "China", "North Korea", "Iran", "Brazil"}


# ── Output dataclass ──────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    final_risk_score:  int   = 0
    severity:          str   = "🟢 Low"
    is_threat:         bool  = False
    rules_score:       float = 0.0
    rules_reasons:     list  = field(default_factory=list)
    anomaly_score:     float = 0.0
    anomaly_label:     str   = "🟢 Normal"
    baseline_score:    float = 0.0
    baseline_reasons:  list  = field(default_factory=list)
    fusion_weights:    dict  = field(default_factory=dict)
    timestamp:         str   = ""

    def to_dict(self):
        return asdict(self)

    def summary(self):
        v = "🚨 THREAT" if self.is_threat else "✅ BENIGN"
        return (
            f"{v} | Risk: {self.final_risk_score}/100 | {self.severity}\n"
            f"  Rules:    {self.rules_score:.1f}/100\n"
            f"  Anomaly:  {self.anomaly_score:.1f}/100 — {self.anomaly_label}\n"
            f"  Baseline: {self.baseline_score:.1f}/100"
        )


# ── Layer 1: Rules engine ─────────────────────────────────────────────────────
# Transparent, documented heuristics. Every rule cites the observable signal.

def _rules_score(log: dict, feat: dict) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    try:
        failed = max(0, int(log.get("failed_logins") or 0))
    except (TypeError, ValueError):
        failed = 0

    # Failed-login volume (real counts supplied by caller/parser)
    if failed >= 30:
        score += 45; reasons.append(f"Extreme failed-login count ({failed})")
    elif failed >= 15:
        score += 30; reasons.append(f"High failed-login count ({failed})")
    elif failed >= 8:
        score += 15; reasons.append(f"Elevated failed-login count ({failed})")
    elif failed >= 4:
        score += 8;  reasons.append(f"Moderate failed-login count ({failed})")

    # Known-malicious process / obfuscated command line (parser-observed)
    if feat.get("process_risk"):
        score += 40
        reasons.append("Known-malicious process or suspicious command line observed")

    # High-severity event category (heuristic weight, not a label)
    er = feat.get("event_risk", 0)
    if er >= 30:
        score += 20
        reasons.append(f"High-severity event type ({log.get('alert_type', '?')})")
    elif er >= 15:
        score += 10
        reasons.append(f"Elevated-severity event type ({log.get('alert_type', '?')})")

    # Off-hours activity
    if feat.get("is_off_hours"):
        score += 10
        reasons.append("Off-hours activity (00–06 or 22–24 UTC)")

    # Geography heuristic
    loc = str(log.get("location", "Unknown"))
    if loc in HIGH_RISK_LOCATIONS:
        score += 10
        reasons.append(f"Source region often seen in opportunistic attacks ({loc})")

    return min(round(score, 1), 100.0), reasons


# ── Layer 3: Statistical baseline ─────────────────────────────────────────────
# Fit on the BENIGN baseline's failed-login distribution. Flags statistical
# deviation — z-score and tail percentiles. No labels involved.

class StatisticalBaseline:
    def __init__(self):
        self.baseline: dict = {}

    def fit_from_csv(self, path: str) -> "StatisticalBaseline":
        import csv
        vals = []
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                try:
                    vals.append(max(0, int(row.get("failed_logins") or 0)))
                except (TypeError, ValueError):
                    pass
        if len(vals) < 100:
            raise ValueError(f"Need >= 100 baseline rows, got {len(vals)}.")
        import statistics
        mean = statistics.fmean(vals)
        std = statistics.pstdev(vals) or 1.0
        s = sorted(vals)
        p95 = float(s[int(0.95 * len(s))])
        p99 = float(s[int(0.99 * len(s))])
        self.baseline = {
            "failed_logins": {"mean": mean, "std": std,
                              "p95": p95, "p99": p99,
                              "n": len(vals)},
            "built_at": datetime.now(timezone.utc).isoformat(),
        }
        return self

    def save(self, path: str = _BASELINE_PATH) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.baseline, f, indent=2)

    def load(self, path: str = _BASELINE_PATH) -> "StatisticalBaseline":
        with open(path) as f:
            self.baseline = json.load(f)
        return self

    def deviation_score(self, log: dict) -> tuple[float, list[str]]:
        if not self.baseline:
            return 0.0, []
        try:
            fl = float(log.get("failed_logins") or 0)
        except (TypeError, ValueError):
            fl = 0.0
        st = self.baseline.get("failed_logins", {})
        mean, std = st.get("mean", 2.0), st.get("std", 1.0)
        p95, p99 = st.get("p95", 5.0), st.get("p99", 8.0)
        z = (fl - mean) / std if std > 0 else 0.0
        score, reasons = 0.0, []
        if fl > p99:
            score += min(40.0, 15.0 + (fl - p99) * 2)
            reasons.append(
                f"Failed logins ({fl:.0f}) exceed 99th percentile of benign "
                f"baseline ({p99:.1f}) — Z={z:.1f}")
        elif fl > p95:
            score += min(20.0, 8.0 + (fl - p95) * 1.5)
            reasons.append(
                f"Failed logins ({fl:.0f}) above 95th percentile of benign "
                f"baseline ({p95:.1f}) — Z={z:.1f}")
        elif z > 2.0:
            score += 10.0
            reasons.append(f"Failed logins statistically elevated — Z={z:.1f}")
        return min(round(score, 1), 100.0), reasons


# ── Lazy layer loading (no training at import time) ───────────────────────────

_layers: dict = {}


def _get_layers() -> StatisticalBaseline:
    """Load (or build) the statistical baseline. Anomaly model lazy-loads itself."""
    if "baseline" not in _layers:
        bl = StatisticalBaseline()
        if os.path.exists(_BASELINE_PATH):
            try:
                bl.load(_BASELINE_PATH)
            except Exception as e:
                print(f"[detection_engine] Baseline unreadable ({e}) — rebuilding.")
                bl = _build_baseline()
        else:
            bl = _build_baseline()
        _layers["baseline"] = bl
    return _layers["baseline"]


def _build_baseline() -> StatisticalBaseline:
    csv_path = os.path.join(_BASE, "data", "baseline_benign.csv")
    bl = StatisticalBaseline().fit_from_csv(csv_path)
    bl.save(_BASELINE_PATH)
    print("[detection_engine] Statistical baseline built from benign data.")
    return bl


# ── Fusion ────────────────────────────────────────────────────────────────────

def _fuse(rules: float, anomaly: float, baseline: float) -> tuple[int, str]:
    raw = (WEIGHTS["rules"] * rules
           + WEIGHTS["anomaly"] * anomaly
           + WEIGHTS["baseline"] * baseline)
    # Agreement bonus: all three layers firing is stronger evidence
    if rules >= 60 and anomaly >= 60 and baseline >= 60:
        raw = min(raw + 10.0, 100.0)
    final = int(round(min(raw, 100.0)))
    sev = ("🔴 Critical" if final >= 80 else
           "🟠 High"     if final >= 60 else
           "🟡 Medium"   if final >= 35 else
           "🟢 Low")
    return final, sev


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(log: dict) -> DetectionResult:
    """
    Score one parsed log dict. Input is the RAW log (event_id, timestamp,
    alert_type, failed_logins, source_ip, ...). Feature extraction happens
    inside — callers never build model features by hand.
    """
    baseline = _get_layers()
    feat = extract_features(log)

    rules_score, rules_reasons       = _rules_score(log, feat)
    anomaly_score, anomaly_label     = anomaly_model.score_event(log)
    baseline_score, baseline_reasons = baseline.deviation_score(log)

    final, severity = _fuse(rules_score, anomaly_score, baseline_score)

    return DetectionResult(
        final_risk_score = final,
        severity         = severity,
        is_threat        = final >= 35,
        rules_score      = rules_score,
        rules_reasons    = rules_reasons,
        anomaly_score    = anomaly_score,
        anomaly_label    = anomaly_label,
        baseline_score   = baseline_score,
        baseline_reasons = baseline_reasons,
        fusion_weights   = dict(WEIGHTS),
        timestamp        = datetime.now(timezone.utc).isoformat(),
    )


def analyze_batch(logs: list[dict]) -> list[DetectionResult]:
    # Warm the lazy layers once, then score (anomaly model batches internally)
    _get_layers()
    if not logs:
        return []
    anom = anomaly_model.score_batch(logs)
    baseline = _layers["baseline"]
    out = []
    for log, (a_score, a_label) in zip(logs, anom):
        feat = extract_features(log)
        r_score, r_reasons = _rules_score(log, feat)
        b_score, b_reasons = baseline.deviation_score(log)
        final, severity = _fuse(r_score, a_score, b_score)
        out.append(DetectionResult(
            final_risk_score=final, severity=severity, is_threat=final >= 35,
            rules_score=r_score, rules_reasons=r_reasons,
            anomaly_score=a_score, anomaly_label=a_label,
            baseline_score=b_score, baseline_reasons=b_reasons,
            fusion_weights=dict(WEIGHTS),
            timestamp=datetime.now(timezone.utc).isoformat(),
        ))
    return out


def retrain() -> None:
    """Delete persisted artifacts so next analyze() rebuilds from baseline."""
    _layers.clear()
    anomaly_model._model_cache.clear()
    for p in (_BASELINE_PATH, anomaly_model._ISO_PATH):
        if os.path.exists(p):
            os.remove(p)
    print("[detection_engine] Artifacts cleared — will rebuild on next run.")


def get_layer_status() -> dict:
    bl = _layers.get("baseline")
    info = anomaly_model.model_info() if _layers else {}
    return {
        "rules_engine":         {"loaded": True, "type": "heuristic"},
        "isolation_forest":     {"loaded": bool(info), **info},
        "statistical_baseline": {"loaded": bool(bl and bl.baseline),
                                 "built_at": (bl.baseline.get("built_at", "")
                                              if bl else "")},
    }


if __name__ == "__main__":
    print("Detection Engine self-test\n" + "=" * 40)
    for name, log in [
        ("benign login",  {"event_id": "4624", "timestamp": "2026-01-06T10:15:00+00:00",
                           "alert_type": "Normal Login", "failed_logins": 1,
                           "source_ip": "192.168.1.10", "location": "India",
                           "device": "Windows"}),
        ("brute force",   {"event_id": "4625", "timestamp": "2026-01-06T10:16:00+00:00",
                           "alert_type": "Brute Force", "failed_logins": 35,
                           "source_ip": "45.33.32.1", "location": "Russia",
                           "device": "Linux"}),
        ("lsass 3am",     {"event_id": "10", "timestamp": "2026-01-06T03:12:00+00:00",
                           "alert_type": "Credential Dumping", "failed_logins": 0,
                           "source_ip": "45.33.32.1", "process_risk": 1}),
    ]:
        r = analyze(log)
        print(f"\n▶ {name}")
        print(r.summary())
        for rsn in r.rules_reasons:
            print(f"    · {rsn}")
