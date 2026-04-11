"""
detection_engine.py
═══════════════════
Hybrid SOC Detection Engine

Layer 1 — GradientBoosting ML classifier     (weight: 40%)
Layer 2 — Isolation Forest anomaly detector  (weight: 30%)
Layer 3 — Statistical baseline deviation     (weight: 30%)

Key fixes vs previous version:
  - train_test_split now has safe fallback when stratify fails
  - All model loading wrapped in try/except (corrupt file recovery)
  - Anomaly feature builder uses fillna(0) throughout
  - No NaN can reach sklearn from this module
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

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

_BASE          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR     = os.path.join(_BASE, "model")
_GB_PATH       = os.path.join(_MODEL_DIR, "model.pkl")
_ISO_PATH      = os.path.join(_MODEL_DIR, "isolation_forest.pkl")
_SCALER_PATH   = os.path.join(_MODEL_DIR, "scaler.pkl")
_BASELINE_PATH = os.path.join(_MODEL_DIR, "baseline.json")

os.makedirs(_MODEL_DIR, exist_ok=True)

WEIGHTS = {"ml": 0.40, "anomaly": 0.30, "baseline": 0.30}

HIGH_RISK_LOCATIONS = {"Russia", "China", "North Korea", "Brazil", "Iran"}
ATTACK_TYPES = {
    "Brute Force", "Credential Stuffing", "Password Spray",
    "Suspicious Login", "Suspicious Activity",
    "Malware Execution", "Privilege Escalation", "Credential Dumping",
}


# ── Output dataclass ──────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    final_risk_score:  int   = 0
    severity:          str   = "🟢 Low"
    is_threat:         bool  = False
    ml_score:          float = 0.0
    ml_confidence:     float = 0.0
    ml_prediction:     int   = 0
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
            f"  ML:       {self.ml_score:.1f}/100 (conf {self.ml_confidence:.0%})\n"
            f"  Anomaly:  {self.anomaly_score:.1f}/100 — {self.anomaly_label}\n"
            f"  Baseline: {self.baseline_score:.1f}/100"
        )


# ── Layer 1: GradientBoosting ─────────────────────────────────────────────────

def _train_gb(X, y):
    # Use stratify only when safe
    min_class = int(y.value_counts().min())
    use_strat = min_class >= 2
    n_test    = max(1, int(len(X) * 0.2))

    # Need at least 1 sample per class in test set when stratifying
    if use_strat and n_test < 2:
        use_strat = False

    try:
        Xtr, _, ytr, _ = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y if use_strat else None,
        )
    except ValueError as e:
        print(f"[detection_engine] Stratified split failed ({e}). "
              "Training on full dataset.")
        Xtr, ytr = X, y

    m = GradientBoostingClassifier(
        n_estimators=150, learning_rate=0.1,
        max_depth=4, random_state=42,
    )
    m.fit(Xtr, ytr)
    return m


def _load_or_train_gb():
    if os.path.exists(_GB_PATH):
        try:
            return joblib.load(_GB_PATH)
        except Exception as e:
            print(f"[detection_engine] GB model corrupt ({e}), retraining.")
            os.remove(_GB_PATH)

    from preprocess import load_data
    df = load_data()
    X  = df.drop("label", axis=1)
    y  = df["label"]
    m  = _train_gb(X, y)
    joblib.dump(m, _GB_PATH)
    print("[detection_engine] GradientBoosting trained OK.")
    return m


def _ml_score(model, data: dict):
    df = pd.DataFrame([data])
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0
    df = df[model.feature_names_in_].fillna(0)
    pred  = int(model.predict(df)[0])
    proba = float(model.predict_proba(df)[0][1])
    return round(proba * 100, 1), proba, pred


# ── Layer 2: Isolation Forest ─────────────────────────────────────────────────

def _anom_row(data: dict) -> pd.DataFrame:
    return pd.DataFrame([{
        "failed_logins":         float(data.get("failed_logins", 0)),
        "is_high_risk_location": float(int(any(
            data.get(f"location_{c}", 0) for c in HIGH_RISK_LOCATIONS))),
        "is_attack_type":        float(int(any(
            data.get(f"alert_type_{t}", 0) for t in ATTACK_TYPES))),
        "is_non_windows":        float(int(not data.get("device_Windows", 0))),
    }]).fillna(0)


def _anom_df_from_train(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    out["failed_logins"] = df.get("failed_logins", pd.Series(0, index=df.index)).astype(float)
    hr = [c for c in df.columns if any(loc in c for loc in HIGH_RISK_LOCATIONS)]
    out["is_high_risk_location"] = df[hr].max(axis=1).astype(float) if hr else 0.0
    atk = [c for c in df.columns if c.startswith("alert_type_") and "Normal" not in c]
    out["is_attack_type"] = df[atk].max(axis=1).astype(float) if atk else 0.0
    win = "device_Windows"
    out["is_non_windows"] = (1 - df[win].astype(float)) if win in df.columns else 0.0
    return out.fillna(0)


def _load_or_train_iso():
    if os.path.exists(_ISO_PATH) and os.path.exists(_SCALER_PATH):
        try:
            return joblib.load(_ISO_PATH), joblib.load(_SCALER_PATH)
        except Exception as e:
            print(f"[detection_engine] IsoFor corrupt ({e}), retraining.")
            for p in (_ISO_PATH, _SCALER_PATH):
                if os.path.exists(p): os.remove(p)

    from preprocess import load_data
    df     = load_data()
    Xan    = _anom_df_from_train(df)
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(Xan)
    iso    = IsolationForest(n_estimators=200, contamination=0.40,
                              max_features=1.0, random_state=42)
    iso.fit(Xs)
    joblib.dump(iso,    _ISO_PATH)
    joblib.dump(scaler, _SCALER_PATH)
    print("[detection_engine] Isolation Forest trained OK.")
    return iso, scaler


def _compute_anomaly(iso, scaler, data: dict):
    Xs    = scaler.transform(_anom_row(data).values)
    raw   = float(iso.decision_function(Xs)[0])
    pred  = int(iso.predict(Xs)[0])
    score = round((0.5 - max(-0.5, min(0.5, raw))) * 100, 1)
    label = "🔴 Anomaly Detected" if pred == -1 else "🟢 Normal"
    return score, label


# ── Layer 3: Statistical Baseline ────────────────────────────────────────────

class StatisticalBaseline:
    def __init__(self):
        self.baseline: dict = {}

    def fit(self, df: pd.DataFrame):
        normal = df[df["label"] == 0]
        if normal.empty:
            return self
        fl = normal["failed_logins"].dropna()
        self.baseline["failed_logins"] = {
            "mean": float(fl.mean()),
            "std":  float(fl.std()) if fl.std() > 0 else 1.0,
            "p95":  float(fl.quantile(0.95)),
            "p99":  float(fl.quantile(0.99)),
        }
        for col in [c for c in df.columns if c.startswith("location_")]:
            country = col.replace("location_", "")
            self.baseline.setdefault("location_threat_rates", {})[country] = {
                "threat_rate": round(
                    int(df[df["label"] == 1][col].sum()) / max(int(df[col].sum()), 1), 3)
            }
        for col in [c for c in df.columns if c.startswith("alert_type_")]:
            atype = col.replace("alert_type_", "")
            self.baseline.setdefault("attack_type_threat_rates", {})[atype] = {
                "threat_rate": round(
                    int(df[df["label"] == 1][col].sum()) / max(int(df[col].sum()), 1), 3)
            }
        self.baseline["built_at"] = datetime.utcnow().isoformat()
        return self

    def save(self, path=_BASELINE_PATH):
        with open(path, "w") as f:
            json.dump(self.baseline, f, indent=2)

    def load(self, path=_BASELINE_PATH):
        with open(path) as f:
            self.baseline = json.load(f)
        return self

    def deviation_score(self, data: dict):
        if not self.baseline:
            return 0.0, []
        score, reasons = 0.0, []
        fl    = float(data.get("failed_logins", 0))
        st    = self.baseline.get("failed_logins", {})
        mean, std = st.get("mean", 2.0), st.get("std", 1.0)
        p95,  p99 = st.get("p95",  5.0), st.get("p99", 8.0)
        z = (fl - mean) / std if std > 0 else 0.0
        if fl > p99:
            score += min(40.0, 15.0 + (fl - p99) * 2)
            reasons.append(f"Failed logins ({fl:.0f}) exceed 99th pct of normal ({p99:.1f}) — Z={z:.1f}")
        elif fl > p95:
            score += min(20.0, 8.0 + (fl - p95) * 1.5)
            reasons.append(f"Failed logins ({fl:.0f}) above 95th pct of normal ({p95:.1f}) — Z={z:.1f}")
        elif z > 2.0:
            score += 10.0
            reasons.append(f"Failed logins statistically elevated — Z={z:.1f}")
        for country, s in self.baseline.get("location_threat_rates", {}).items():
            if data.get(f"location_{country}", 0):
                r = s.get("threat_rate", 0.0)
                if r >= 0.9: score += 25.0; reasons.append(f"Location '{country}' — {r*100:.0f}% threat rate")
                elif r >= 0.6: score += 15.0; reasons.append(f"Location '{country}' — elevated ({r*100:.0f}%)")
                elif r >= 0.3: score += 8.0;  reasons.append(f"Location '{country}' — moderate risk ({r*100:.0f}%)")
                break
        for atype, s in self.baseline.get("attack_type_threat_rates", {}).items():
            if data.get(f"alert_type_{atype}", 0):
                r = s.get("threat_rate", 0.0)
                if r >= 0.95: score += 30.0; reasons.append(f"'{atype}' is {r*100:.0f}% correlated with threats")
                elif r >= 0.70: score += 18.0; reasons.append(f"'{atype}' high threat correlation ({r*100:.0f}%)")
                break
        return min(round(score, 1), 100.0), reasons


def _load_or_build_baseline():
    bl = StatisticalBaseline()
    if os.path.exists(_BASELINE_PATH):
        try:
            return bl.load(_BASELINE_PATH)
        except Exception as e:
            print(f"[detection_engine] Baseline corrupt ({e}), rebuilding.")
            os.remove(_BASELINE_PATH)
    from preprocess import load_data
    bl.fit(load_data()).save(_BASELINE_PATH)
    print("[detection_engine] Statistical baseline built OK.")
    return bl


# ── Module startup ────────────────────────────────────────────────────────────

def _safe_load_all():
    try:
        gb = _load_or_train_gb()
    except Exception as e:
        raise RuntimeError(
            f"GradientBoosting load/train failed: {e}\n"
            "Ensure data/sample_logs.csv has valid rows with label 0 and 1."
        ) from e
    try:
        iso, scl = _load_or_train_iso()
    except Exception as e:
        raise RuntimeError(f"Isolation Forest load/train failed: {e}") from e
    try:
        bl = _load_or_build_baseline()
    except Exception as e:
        raise RuntimeError(f"Statistical baseline build failed: {e}") from e
    return gb, iso, scl, bl


_gb_model, _iso, _scl, _baseline = _safe_load_all()


# ── Fusion ────────────────────────────────────────────────────────────────────

def _fuse(ml, anomaly, baseline, ml_pred):
    raw = WEIGHTS["ml"] * ml + WEIGHTS["anomaly"] * anomaly + WEIGHTS["baseline"] * baseline
    if ml_pred == 1 and ml >= 70:
        raw = max(raw, 50.0)
    if ml >= 60 and anomaly >= 60 and baseline >= 60:
        raw = min(raw + 10.0, 100.0)
    final = int(round(min(raw, 100.0)))
    sev   = ("🔴 Critical" if final >= 80 else
             "🟠 High"     if final >= 60 else
             "🟡 Medium"   if final >= 35 else
             "🟢 Low")
    return final, sev


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(data: dict) -> DetectionResult:
    ml_score, ml_conf, ml_pred    = _ml_score(_gb_model, data)
    anomaly_score, anomaly_label  = _compute_anomaly(_iso, _scl, data)
    baseline_score, baseline_rsns = _baseline.deviation_score(data)
    final, severity               = _fuse(ml_score, anomaly_score, baseline_score, ml_pred)
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


def analyze_batch(events: list) -> list:
    return [analyze(e) for e in events]


def retrain_all():
    global _gb_model, _iso, _scl, _baseline
    for p in (_GB_PATH, _ISO_PATH, _SCALER_PATH, _BASELINE_PATH):
        if os.path.exists(p): os.remove(p)
    _gb_model, _iso, _scl, _baseline = _safe_load_all()
    print("[detection_engine] All layers retrained.")


def get_baseline_stats() -> dict:
    return _baseline.baseline


def get_layer_status() -> dict:
    return {
        "gradient_boosting":    {"loaded": _gb_model is not None,
                                  "features": len(_gb_model.feature_names_in_) if _gb_model else 0},
        "isolation_forest":     {"loaded": _iso is not None},
        "statistical_baseline": {"loaded": bool(_baseline.baseline),
                                  "built_at": _baseline.baseline.get("built_at", "")},
    }


if __name__ == "__main__":
    print("Detection Engine self-test\n" + "="*40)
    for name, data in [
        ("Normal",        {"failed_logins": 1, "location_India": 1, "device_Windows": 1, "alert_type_Normal Login": 1}),
        ("Brute Force",   {"failed_logins": 35, "location_Russia": 1, "device_Linux": 1, "alert_type_Brute Force": 1}),
        ("Cred Dump",     {"failed_logins": 40, "location_Russia": 1, "device_Linux": 1, "alert_type_Credential Dumping": 1}),
    ]:
        r = analyze(data)
        print(f"\n▶ {name}")
        print(r.summary())
