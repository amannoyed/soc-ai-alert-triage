import joblib
import pandas as pd
import os
import requests
import sys

sys.path.append(os.path.dirname(__file__))

base_path = os.path.dirname(os.path.dirname(__file__))
model_dir = os.path.join(base_path, "model")
model_path = os.path.join(model_dir, "model.pkl")

# ── Auto-train if model missing ──────────────────────────────────────────────

def _ensure_model():
    if not os.path.exists(model_path):
        from train_model import train
        return train()
    return joblib.load(model_path)


model = _ensure_model()

# ── API Key ───────────────────────────────────────────────────────────────────
# Set via Streamlit secrets or environment variable

def _get_api_key():
    try:
        import streamlit as st
        return st.secrets.get("ABUSEIPDB_API_KEY", "")
    except Exception:
        return os.getenv("ABUSEIPDB_API_KEY", "")


# ── Known malicious IPs (fallback when API unavailable) ──────────────────────

KNOWN_BAD_IPS = {
    "10.0.0.5", "45.33.32.1", "185.220.101.1", "103.21.244.0",
    "77.88.55.1", "31.13.72.1", "46.166.185.1", "91.108.4.1",
    "149.154.167.1", "5.9.32.1", "66.102.0.1", "62.210.0.1"
}

# ── IP Reputation ─────────────────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> tuple[str, int]:
    """Returns (status_string, abuse_score 0-100)."""
    # Skip private / loopback
    if ip.startswith(("192.168.", "10.", "172.", "127.", "8.8.")):
        return "🟢 Internal / Clean IP", 0

    api_key = _get_api_key()

    if api_key:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            data = resp.json()
            score = data["data"]["abuseConfidenceScore"]
            country = data["data"].get("countryCode", "??")

            if score >= 75:
                return f"🔴 Malicious IP [{country}] (Score: {score})", score
            elif score >= 30:
                return f"🟡 Suspicious IP [{country}] (Score: {score})", score
            else:
                return f"🟢 Clean IP [{country}] (Score: {score})", score
        except Exception:
            pass  # Fall through to local check

    # Local fallback
    if ip in KNOWN_BAD_IPS:
        return f"🔴 Malicious IP (local threat list)", 90
    return "🟢 Clean IP (no local match)", 0


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────

MITRE_MAP = {
    "Brute Force":          [("T1110",     "Brute Force")],
    "Credential Stuffing":  [("T1110.004", "Credential Stuffing")],
    "Password Spray":       [("T1110.003", "Password Spraying")],
    "Suspicious Login":     [("T1078",     "Valid Accounts")],
    "Suspicious Activity":  [("T1059",     "Command & Scripting Interpreter")],
    "Malware Execution":    [("T1059.001", "PowerShell"), ("T1204", "User Execution")],
    "Credential Dumping":   [("T1003",     "OS Credential Dumping")],
    "Privilege Escalation": [("T1068",     "Exploitation for Privilege Escalation")],
}


def map_mitre(alert_type: str) -> list[str]:
    entries = MITRE_MAP.get(alert_type, [])
    return [f"{tid} — {name}" for tid, name in entries]


# ── Risk Scoring Engine ───────────────────────────────────────────────────────

GEO_RISK = {
    "North Korea": 40,
    "Russia":      25,
    "China":       20,
    "Brazil":      10,
    "US":          5,
    "Germany":     5,
    "UK":          5,
    "India":       3,
}

ATTACK_RISK = {
    "Brute Force":          35,
    "Credential Stuffing":  40,
    "Password Spray":       30,
    "Suspicious Login":     20,
    "Suspicious Activity":  25,
    "Malware Execution":    45,
    "Credential Dumping":   50,
    "Privilege Escalation": 45,
    "Normal Login":         0,
}


def calculate_risk_score(data: dict, ip_score: int) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    failed = data.get("failed_logins", 0)

    if failed >= 30:
        score += 45
        reasons.append(f"Extreme login failures ({failed})")
    elif failed >= 15:
        score += 30
        reasons.append(f"High login failures ({failed})")
    elif failed >= 8:
        score += 15
        reasons.append(f"Moderate login failures ({failed})")

    # Attack type contribution
    for key, val in ATTACK_RISK.items():
        col = f"alert_type_{key}"
        if data.get(col, 0) and val > 0:
            score += val
            reasons.append(f"Attack type: {key}")
            break  # Only count once

    # Geo risk
    for country, geo_val in GEO_RISK.items():
        if data.get(f"location_{country}", 0):
            score += geo_val
            reasons.append(f"High-risk region: {country}")
            break

    # IP reputation
    ip_contribution = int(ip_score * 0.6)
    if ip_contribution > 0:
        score += ip_contribution
        reasons.append(f"IP reputation score: {ip_score}")

    return min(score, 100), reasons


def get_severity(score: int) -> str:
    if score >= 80:
        return "🔴 Critical"
    elif score >= 60:
        return "🟠 High"
    elif score >= 35:
        return "🟡 Medium"
    else:
        return "🟢 Low"


# ── Main Prediction Function ──────────────────────────────────────────────────

def predict_alert(data: dict, ip: str = "8.8.8.8") -> tuple:
    df = pd.DataFrame([data])

    # Align to training features
    for col in model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0

    df = df[model.feature_names_in_]

    ml_prediction = int(model.predict(df)[0])
    ml_confidence = float(model.predict_proba(df)[0][1])  # prob of being threat

    # Determine alert type from data
    alert_type = "Normal Login"
    for key in ATTACK_RISK:
        if data.get(f"alert_type_{key}", 0):
            alert_type = key
            break

    # IP intel
    ip_status, ip_score = check_ip_reputation(ip)

    # Risk
    risk_score, reasons = calculate_risk_score(data, ip_score)

    # Override: if ML says threat but score is low, bump it
    if ml_prediction == 1 and risk_score < 30:
        risk_score = max(risk_score, 35)
        reasons.append("ML model flagged as threat")

    severity = get_severity(risk_score)
    mitre = map_mitre(alert_type)

    # Anomaly
    if data.get("failed_logins", 0) >= 20 or ip_score >= 70:
        anomaly = "⚠️ Anomalous Behavior Detected"
    else:
        anomaly = "✅ Normal Behavior"

    if ml_prediction == 1:
        result = f"🚨 Threat Detected (ML confidence: {ml_confidence:.0%})"
    else:
        result = f"✅ Benign Activity (ML confidence: {1 - ml_confidence:.0%})"

    return result, risk_score, severity, mitre, anomaly, ip_status, reasons