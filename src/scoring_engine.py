"""
scoring_engine.py
═════════════════
Dynamic Risk Scoring Engine

Combines:
  - ML confidence score        (from detection_engine)
  - Isolation Forest anomaly   (from detection_engine)
  - Statistical baseline       (from detection_engine)
  - UEBA behavioral anomaly    (from ueba_engine)
  - Correlation severity       (from correlation_engine)
  - Threat intelligence        (AbuseIPDB / local intel)

All weights are configurable via ScoringConfig.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScoringConfig:
    """
    All weights must sum to 1.0.
    Adjust per environment — e.g. raise threat_intel weight if API key available.
    """
    weight_ml:             float = 0.25
    weight_anomaly:        float = 0.20
    weight_baseline:       float = 0.15
    weight_ueba:           float = 0.15
    weight_correlation:    float = 0.15
    weight_threat_intel:   float = 0.10

    # Thresholds
    critical_floor:        int   = 80
    high_floor:            int   = 60
    medium_floor:          int   = 35

    # Override rules
    intel_malicious_boost: int   = 15    # added if IP is known malicious
    chain_confidence_boost: int  = 10    # added if attack chain confidence ≥ 85%
    consensus_boost:       int   = 8     # added if 4+ layers agree score ≥ 60

    def validate(self) -> bool:
        total = (self.weight_ml + self.weight_anomaly + self.weight_baseline +
                 self.weight_ueba + self.weight_correlation + self.weight_threat_intel)
        return abs(total - 1.0) < 0.01

    def renormalize(self) -> "ScoringConfig":
        """Auto-fix weights to sum to 1.0."""
        total = (self.weight_ml + self.weight_anomaly + self.weight_baseline +
                 self.weight_ueba + self.weight_correlation + self.weight_threat_intel)
        if total == 0:
            return self
        factor = 1.0 / total
        self.weight_ml           *= factor
        self.weight_anomaly      *= factor
        self.weight_baseline     *= factor
        self.weight_ueba         *= factor
        self.weight_correlation  *= factor
        self.weight_threat_intel *= factor
        return self


# Default global config (can be replaced by caller)
DEFAULT_CONFIG = ScoringConfig()


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class LayerScore:
    name:         str
    raw_score:    float      # 0–100 input from that layer
    weight:       float
    contribution: float      # raw_score × weight
    note:         str = ""


@dataclass
class ScoringResult:
    final_score:       int
    severity:          str
    confidence_level:  str      # "Very High" | "High" | "Medium" | "Low"
    confidence_pct:    int      # 0–100
    layers:            list[LayerScore]
    overrides_applied: list[str]
    breakdown:         str      # human-readable score explanation
    timestamp:         str

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def breakdown_table(self) -> str:
        lines = [
            f"{'Layer':<20} {'Raw':>6} {'Weight':>8} {'Contrib':>8}",
            "-" * 46,
        ]
        for lyr in self.layers:
            lines.append(
                f"{lyr.name:<20} {lyr.raw_score:>6.1f} "
                f"{lyr.weight:>7.0%} {lyr.contribution:>8.1f}"
            )
        lines.append("-" * 46)
        lines.append(
            f"{'FINAL SCORE':<20} {' ':>6} {' ':>8} {self.final_score:>8}"
        )
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION SEVERITY → SCORE
# ══════════════════════════════════════════════════════════════════════════════

_CORR_SEVERITY_MAP = {
    "Critical": 90,
    "High":     70,
    "Medium":   45,
    "Low":      15,
    "None":      0,
}


def _corr_score(correlation_result) -> float:
    """Convert CorrelationResult to a 0–100 score."""
    if correlation_result is None:
        return 0.0
    # Use the highest-severity alert
    if not hasattr(correlation_result, "alerts") or not correlation_result.alerts:
        return 0.0

    sev_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    top = max(correlation_result.alerts,
              key=lambda a: sev_order.get(a.severity, 0))
    base = _CORR_SEVERITY_MAP.get(top.severity, 0)
    # Blend in attack confidence
    conf_bonus = correlation_result.attack_confidence * 0.1
    return min(base + conf_bonus, 100.0)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCORING FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def compute_score(
    detection_result,               # DetectionResult from detection_engine
    ueba_result,                    # UEBAResult from ueba_engine (or None)
    correlation_result,             # CorrelationResult from correlation_engine (or None)
    ip_abuse_score:  int   = 0,     # 0–100 from AbuseIPDB
    config: ScoringConfig = None,
) -> ScoringResult:
    """
    Compute the final fused risk score from all detection layers.

    Parameters
    ----------
    detection_result   : DetectionResult
    ueba_result        : UEBAResult | None
    correlation_result : CorrelationResult | None
    ip_abuse_score     : int 0–100 (AbuseIPDB confidence score)
    config             : ScoringConfig (uses DEFAULT_CONFIG if None)

    Returns
    -------
    ScoringResult
    """
    cfg = config or DEFAULT_CONFIG
    if not cfg.validate():
        cfg = cfg.renormalize()

    # ── Extract raw scores from each layer ────────────────────────────────────
    ml_raw       = float(getattr(detection_result, "ml_score",       0))
    anomaly_raw  = float(getattr(detection_result, "anomaly_score",  0))
    baseline_raw = float(getattr(detection_result, "baseline_score", 0))
    ueba_raw     = float(getattr(ueba_result,       "anomaly_score",  0)) \
                   if ueba_result is not None else 0.0
    corr_raw     = _corr_score(correlation_result)
    intel_raw    = float(ip_abuse_score)

    # ── Weighted contributions ────────────────────────────────────────────────
    layers = [
        LayerScore("ML Classifier",   ml_raw,       cfg.weight_ml,
                   ml_raw       * cfg.weight_ml,
                   f"GradientBoosting P(threat)={ml_raw:.1f}%"),
        LayerScore("Anomaly (IsoFor)",anomaly_raw,  cfg.weight_anomaly,
                   anomaly_raw  * cfg.weight_anomaly,
                   f"Isolation Forest deviation={anomaly_raw:.1f}"),
        LayerScore("Stat. Baseline",  baseline_raw, cfg.weight_baseline,
                   baseline_raw * cfg.weight_baseline,
                   f"Z-score / percentile deviation={baseline_raw:.1f}"),
        LayerScore("UEBA",            ueba_raw,     cfg.weight_ueba,
                   ueba_raw     * cfg.weight_ueba,
                   f"Behavioral anomaly={ueba_raw:.1f}"),
        LayerScore("Correlation",     corr_raw,     cfg.weight_correlation,
                   corr_raw     * cfg.weight_correlation,
                   f"Highest correlation severity score={corr_raw:.1f}"),
        LayerScore("Threat Intel",    intel_raw,    cfg.weight_threat_intel,
                   intel_raw    * cfg.weight_threat_intel,
                   f"AbuseIPDB abuse score={intel_raw:.0f}"),
    ]

    weighted_sum = sum(lyr.contribution for lyr in layers)

    # ── Override / boost rules ────────────────────────────────────────────────
    overrides: list[str] = []

    # Rule 1 — Known malicious IP
    if ip_abuse_score >= 75:
        weighted_sum += cfg.intel_malicious_boost
        overrides.append(
            f"+{cfg.intel_malicious_boost} — IP confirmed malicious "
            f"(AbuseIPDB={ip_abuse_score})"
        )

    # Rule 2 — Strong attack chain
    if (correlation_result is not None
            and getattr(correlation_result, "attack_confidence", 0) >= 85):
        weighted_sum += cfg.chain_confidence_boost
        overrides.append(
            f"+{cfg.chain_confidence_boost} — Attack chain confidence "
            f"{correlation_result.attack_confidence}% ≥ 85%"
        )

    # Rule 3 — ML floor when classifier is confident
    ml_pred = int(getattr(detection_result, "ml_prediction", 0))
    if ml_pred == 1 and ml_raw >= 75:
        if weighted_sum < 50:
            weighted_sum = 50.0
            overrides.append("+floor=50 — ML confident threat prediction")

    # Rule 4 — Multi-layer consensus
    high_count = sum(
        1 for s in [ml_raw, anomaly_raw, baseline_raw, ueba_raw, corr_raw]
        if s >= 60
    )
    if high_count >= 4:
        weighted_sum += cfg.consensus_boost
        overrides.append(
            f"+{cfg.consensus_boost} — Consensus: {high_count}/5 layers ≥ 60"
        )

    final = int(round(min(weighted_sum, 100.0)))

    # ── Severity ──────────────────────────────────────────────────────────────
    severity = ("🔴 Critical" if final >= cfg.critical_floor else
                "🟠 High"     if final >= cfg.high_floor     else
                "🟡 Medium"   if final >= cfg.medium_floor   else
                "🟢 Low")

    # ── Confidence level ──────────────────────────────────────────────────────
    # Based on how many layers contributed a meaningful signal
    contributing = sum(1 for lyr in layers if lyr.raw_score >= 20)
    if contributing >= 5:
        conf_label, conf_pct = "Very High", 95
    elif contributing >= 4:
        conf_label, conf_pct = "High",      80
    elif contributing >= 3:
        conf_label, conf_pct = "Medium",    65
    elif contributing >= 2:
        conf_label, conf_pct = "Low",       45
    else:
        conf_label, conf_pct = "Very Low",  25

    # ── Breakdown text ────────────────────────────────────────────────────────
    top3 = sorted(layers, key=lambda l: l.contribution, reverse=True)[:3]
    top3_str = " + ".join(f"{l.name}({l.raw_score:.0f})" for l in top3)
    breakdown = (
        f"Final score {final}/100 driven by: {top3_str}. "
        f"{len(overrides)} override(s) applied."
    )

    return ScoringResult(
        final_score       = final,
        severity          = severity,
        confidence_level  = conf_label,
        confidence_pct    = conf_pct,
        layers            = layers,
        overrides_applied = overrides,
        breakdown         = breakdown,
        timestamp         = datetime.now(timezone.utc).isoformat(),
    )


def compute_score_from_batch(
    detection_results:  list,
    ueba_results:       list,
    correlation_result,
    ip_abuse_scores:    dict,          # {ip_str: score}
    config: ScoringConfig = None,
) -> ScoringResult:
    """
    Aggregate scoring for a batch of events (e.g. full log file analysis).
    Uses the worst-case detection result and max IP abuse score.
    """
    if not detection_results:
        from dataclasses import field as _f
        return ScoringResult(0, "🟢 Low", "Very Low", 0, [], [],
                             "No events to score.",
                             datetime.now(timezone.utc).isoformat())

    # Worst-case detection result = highest final_risk_score
    worst_det = max(detection_results,
                    key=lambda d: getattr(d, "final_risk_score", 0))

    # Worst-case UEBA
    worst_ueba = None
    if ueba_results:
        worst_ueba = max(ueba_results,
                         key=lambda u: getattr(u, "anomaly_score", 0))

    max_intel = max(ip_abuse_scores.values(), default=0)

    return compute_score(
        detection_result   = worst_det,
        ueba_result        = worst_ueba,
        correlation_result = correlation_result,
        ip_abuse_score     = max_intel,
        config             = config,
    )


if __name__ == "__main__":
    print("Scoring Engine — Config validation")
    cfg = ScoringConfig()
    print(f"  Valid: {cfg.validate()}")
    print(f"  Weights: ML={cfg.weight_ml} Anom={cfg.weight_anomaly} "
          f"Base={cfg.weight_baseline} UEBA={cfg.weight_ueba} "
          f"Corr={cfg.weight_correlation} Intel={cfg.weight_threat_intel}")
