"""
detection_engine.py
═══════════════════
Hybrid SOC Detection Engine

Three intelligence layers fused into one final risk score:
  Layer 1 — GradientBoosting ML classifier     (weight: 40%)
  Layer 2 — Isolation Forest anomaly detector  (weight: 30%)
  Layer 3 — Statistical baseline deviation     (weight: 30%)
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from dataclasses import dataclass, field, asdict
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

sys.path.append(os.path.dirname(__file__))

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR     = os.path.join(_BASE, "model")
_GB_PATH       = os.path.join(_MODEL_DIR, "model.pkl")
_ISO_PATH      = os.path.join(_MODEL_DIR, "isolation_forest.pkl")
_SCALER_PATH   = os.path.join(_MODEL_DIR, "scaler.pkl")
_BASELINE_PATH = os.path.join(_MODEL_DIR, "baseline.json")

os.makedirs(_MODEL_DIR, exist_ok=True)

# ── Fusion weights (configurable) ─────────────────────────────────────────────
WEIGHTS = {"ml": 0.40, "anomaly": 0.30, "baseline": 0.30}

HIGH_RISK_LOCATIONS = {"Russia", "China", "North Korea", "Brazil", "Iran"}
ATTACK_TYPES = {
    "Brute Force", "Credential Stuffing", "Password Spray",
    "Suspicious Login", "Suspicious Activity",
    "Malware Execution", "Privilege Escalation", "Credential Dumping",
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASS — structured output
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionResult:
    final_risk_score:  int   = 0
    severity:          str   = "🟢 Low"
    is_threat:         bool  = False
    # Layer 1
    ml_score:          float = 0.0
    ml_confidence:     float = 0.0
    ml_prediction:     int   = 0
    # Layer 2
    anomaly_score:     float = 0.0
    anomaly_label:     str   = "🟢 Normal"
    # Layer 3
    baseline_score:    float = 0.0
    baseline_reasons:  list  = field(default_factory=list)
    # Meta
    fusion_weights:    dict  = field(default_factory=dict)
    timestamp:         str   = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        verdict = "🚨 THREAT" if self.is_threat else "✅ BENIGN"
        return (
            f"{verdict} | Risk: {self.final_risk_score}/100 | {self.severity}\n"
            f"  ML:       {self.ml_score:.1f}/100  "
            f"(conf {self.ml_confidence:.0%}, pred={'threat' if self.ml_prediction else 'benign'})\n"
            f"  Anomaly:  {self.anomaly_score:.1f}/100 — {self.anomaly_label}\n"
            f"  Baseline: {self.baseline_score:.1f}/100"
        )


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — GradientBoosting (existing model, unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def _train_gb(X_train, y_train) -> GradientBoostingClassifier:
    m = GradientBoostingClassifier(
        n_estimators=150, learning_rate=0.1, max_depth=4, random_state=42
    )
    m.fit(X_train, y_train)
    return m


def _load_or_train_gb() -> GradientBoostingClassifier:
    if os.path.exists(_GB_PATH):
        return joblib.load(_GB_PATH)
    from preprocess import load_data
    df = load_data()
    X, y = df.drop("label", axis=1), df["label"]
    Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.2,
                                       random_state=42, stratify=y)
    m = _train_gb(Xtr, ytr)
    joblib.dump(m, _GB_PATH)
    return m


def _ml_score(model, data: dict) -> tuple[float, float, int]:
    df = pd.DataFrame([data])
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0
    df = df[model.feature_names_in_]
    pred  = int(model.predict(df)[0])
    proba = float(model.predict_proba(df)[0][1])
    return round(proba * 100, 1), proba, pred


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — Isolation Forest
# ══════════════════════════════════════════════════════════════════════════════

def _anomaly_features(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out["failed_logins"] = df["failed_logins"].astype(float)
    hr = [c for c in df.columns if any(
        loc in c for loc in HIGH_RISK_LOCATIONS)]
    out["is_high_risk_location"] = df[hr].max(axis=1).astype(float) if hr else 0.0
    atk = [c for c in df.columns
           if c.startswith("alert_type_") and "Normal" not in c]
    out["is_attack_type"] = df[atk].max(axis=1).astype(float) if atk else 0.0
    win = "device_Windows"
    out["is_non_windows"] = (1 - df[win].astype(float)) if win in df.columns else 0.0
    return out


def _train_iso(Xan: pd.DataFrame) -> tuple:
    scaler = StandardScaler()
    Xs = scaler.fit_transform(Xan)
    iso = IsolationForest(n_estimators=200, contamination=0.40,
                          max_features=1.0, random_state=42)
    iso.fit(Xs)
    return iso, scaler


def _load_or_train_iso() -> tuple:
    if os.path.exists(_ISO_PATH) and os.path.exists(_SCALER_PATH):
        return joblib.load(_ISO_PATH), joblib.load(_SCALER_PATH)
    from preprocess import load_data
    df  = load_data()
    Xan = _anomaly_features(df)
    iso, scaler = _train_iso(Xan)
    joblib.dump(iso,    _ISO_PATH)
    joblib.dump(scaler, _SCALER_PATH)
    return iso, scaler


def _compute_anomaly(iso, scaler, data: dict) -> tuple[float, str]:
    row = pd.DataFrame([{
        "failed_logins":         data.get("failed_logins", 0),
        "is_high_risk_location": int(any(
            data.get(f"location_{c}", 0) for c in HIGH_RISK_LOCATIONS)),
        "is_attack_type":        int(any(
            data.get(f"alert_type_{t}", 0) for t in ATTACK_TYPES)),
        "is_non_windows":        int(not data.get("device_Windows", 0)),
    }])
    Xs    = scaler.transform(row)
    raw   = float(iso.decision_function(Xs)[0])
    pred  = int(iso.predict(Xs)[0])
    # map [-0.5, 0.5] → [100, 0]
    score = round((0.5 - max(-0.5, min(0.5, raw))) * 100, 1)
    label = "🔴 Anomaly Detected" if pred == -1 else "🟢 Normal"
    return score, label


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Statistical Baseline
# ══════════════════════════════════════════════════════════════════════════════

class StatisticalBaseline:
    def __init__(self):
        self.baseline: dict = {}

    def fit(self, df: pd.DataFrame) -> "StatisticalBaseline":
        normal = df[df["label"] == 0]
        fl = normal["failed_logins"]
        self.baseline["failed_logins"] = {
            "mean": float(fl.mean()),
            "std":  float(fl.std()) if fl.std() > 0 else 1.0,
            "p95":  float(fl.quantile(0.95)),
            "p99":  float(fl.quantile(0.99)),
        }
        loc_cols = [c for c in df.columns if c.startswith("location_")]
        self.baseline["location_threat_rates"] = {
            col.replace("location_", ""): {
                "threat_rate": round(
                    int(df[df["label"] == 1][col].sum()) / max(int(df[col].sum()), 1), 3)
            }
            for col in loc_cols
        }
        atk_cols = [c for c in df.columns if c.startswith("alert_type_")]
        self.baseline["attack_type_threat_rates"] = {
            col.replace("alert_type_", ""): {
                "threat_rate": round(
                    int(df[df["label"] == 1][col].sum()) / max(int(df[col].sum()), 1), 3)
            }
            for col in atk_cols
        }
        self.baseline["built_at"] = datetime.utcnow().isoformat()
        return self

    def save(self, path=_BASELINE_PATH):
        with open(path, "w") as f:
            json.dump(self.baseline, f, indent=2)

    def load(self, path=_BASELINE_PATH) -> "StatisticalBaseline":
        with open(path) as f:
            self.baseline = json.load(f)
        return self

    def deviation_score(self, data: dict) -> tuple[float, list[str]]:
        if not self.baseline:
            return 0.0, []
        score, reasons = 0.0, []

        fl    = float(data.get("failed_logins", 0))
        stats = self.baseline.get("failed_logins", {})
        mean, std = stats.get("mean", 2.0), stats.get("std", 1.0)
        p95,  p99 = stats.get("p95", 5.0),  stats.get("p99", 8.0)
        z = (fl - mean) / std if std > 0 else 0.0

        if fl > p99:
            contrib = min(40.0, 15.0 + (fl - p99) * 2)
            score  += contrib
            reasons.append(f"Failed logins ({fl:.0f}) exceed 99th percentile "
                           f"of normal ({p99:.1f}) — Z={z:.1f}")
        elif fl > p95:
            score  += min(20.0, 8.0 + (fl - p95) * 1.5)
            reasons.append(f"Failed logins ({fl:.0f}) above 95th percentile "
                           f"of normal ({p95:.1f}) — Z={z:.1f}")
        elif z > 2.0:
            score  += 10.0
            reasons.append(f"Failed logins statistically elevated — Z={z:.1f}")

        for country, stats in self.baseline.get("location_threat_rates", {}).items():
            if data.get(f"location_{country}", 0):
                rate = stats.get("threat_rate", 0.0)
                if rate >= 0.9:
                    score += 25.0
                    reasons.append(f"Location '{country}' — {rate*100:.0f}% historical threat rate")
                elif rate >= 0.6:
                    score += 15.0
                    reasons.append(f"Location '{country}' — elevated threat rate ({rate*100:.0f}%)")
                elif rate >= 0.3:
                    score += 8.0
                    reasons.append(f"Location '{country}' — moderate risk ({rate*100:.0f}%)")
                break

        for atype, stats in self.baseline.get("attack_type_threat_rates", {}).items():
            if data.get(f"alert_type_{atype}", 0):
                rate = stats.get("threat_rate", 0.0)
                if rate >= 0.95:
                    score += 30.0
                    reasons.append(f"'{atype}' is {rate*100:.0f}% correlated with threats")
                elif rate >= 0.70:
                    score += 18.0
                    reasons.append(f"'{atype}' has high threat correlation ({rate*100:.0f}%)")
                break

        return min(round(score, 1), 100.0), reasons


def _load_or_build_baseline() -> StatisticalBaseline:
    bl = StatisticalBaseline()
    if os.path.exists(_BASELINE_PATH):
        return bl.load(_BASELINE_PATH)
    from preprocess import load_data
    bl.fit(load_data()).save(_BASELINE_PATH)
    return bl


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE — Load all three layers at import
# ══════════════════════════════════════════════════════════════════════════════

_gb_model  = _load_or_train_gb()
_iso, _scl = _load_or_train_iso()
_baseline  = _load_or_build_baseline()


def retrain_all():
    global _gb_model, _iso, _scl, _baseline
    from preprocess import load_data
    df = load_data()
    X, y = df.drop("label", axis=1), df["label"]
    Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.2,
                                       random_state=42, stratify=y)
    _gb_model = _train_gb(Xtr, ytr)
    joblib.dump(_gb_model, _GB_PATH)
    Xan = _anomaly_features(df)
    _iso, _scl = _train_iso(Xan)
    joblib.dump(_iso,    _ISO_PATH)
    joblib.dump(_scl, _SCALER_PATH)
    _baseline = StatisticalBaseline()
    _baseline.fit(df).save(_BASELINE_PATH)
    print("✅ All three detection layers retrained.")


# ══════════════════════════════════════════════════════════════════════════════
# FUSION
# ══════════════════════════════════════════════════════════════════════════════

def _fuse(ml: float, anomaly: float, baseline: float,
          ml_pred: int) -> tuple[int, str]:
    raw = WEIGHTS["ml"] * ml + WEIGHTS["anomaly"] * anomaly + WEIGHTS["baseline"] * baseline
    if ml_pred == 1 and ml >= 70:
        raw = max(raw, 50.0)
    if ml >= 60 and anomaly >= 60 and baseline >= 60:
        raw = min(raw + 10.0, 100.0)
    final = int(round(min(raw, 100.0)))
    sev = ("🔴 Critical" if final >= 80 else
           "🟠 High"     if final >= 60 else
           "🟡 Medium"   if final >= 35 else
           "🟢 Low")
    return final, sev


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def analyze(data: dict) -> DetectionResult:
    ml_score, ml_conf, ml_pred = _ml_score(_gb_model, data)
    anomaly_score, anomaly_label = _compute_anomaly(_iso, _scl, data)
    baseline_score, baseline_rsns = _baseline.deviation_score(data)
    final, severity = _fuse(ml_score, anomaly_score, baseline_score, ml_pred)

    return DetectionResult(
        final_risk_score = final,
        severity         = severity,
        is_threat        = final >= 35 or ml_pred == 1,
        ml_score         = ml_score,
        ml_confidence    = round(ml_conf, 3),
        ml_prediction    = ml_pred,
        anomaly_score    = anomaly_score,
        anomaly_label    = anomaly_label,
        baseline_score   = round(baseline_score, 1),
        baseline_reasons = baseline_rsns,
        fusion_weights   = dict(WEIGHTS),
        timestamp        = datetime.utcnow().isoformat(),
    )


def analyze_batch(events: list[dict]) -> list[DetectionResult]:
    return [analyze(e) for e in events]


def get_baseline_stats() -> dict:
    return _baseline.baseline


def get_layer_status() -> dict:
    return {
        "gradient_boosting":    {"loaded": _gb_model is not None,
                                  "features": len(_gb_model.feature_names_in_)},
        "isolation_forest":     {"loaded": _iso is not None,
                                  "estimators": _iso.n_estimators},
        "statistical_baseline": {"loaded": bool(_baseline.baseline),
                                  "built_at": _baseline.baseline.get("built_at", "")},
    }


if __name__ == "__main__":
    print("Hybrid Detection Engine — Self-Test\n" + "="*50)
    for name, data in [
        ("Normal — India, Windows",
         {"failed_logins": 1, "location_India": 1,
          "device_Windows": 1, "alert_type_Normal Login": 1}),
        ("Brute Force — Russia, Linux, 35 failures",
         {"failed_logins": 35, "location_Russia": 1,
          "device_Linux": 1, "alert_type_Brute Force": 1}),
        ("Credential Dump — lsass",
         {"failed_logins": 40, "location_Russia": 1,
          "device_Linux": 1, "alert_type_Credential Dumping": 1}),
    ]:
        r = analyze(data)
        print(f"\n▶ {name}")
        print(r.summary())
