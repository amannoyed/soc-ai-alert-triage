import joblib
import pandas as pd
import requests
import os

# 🔥 Load model safely
base_path = os.path.dirname(os.path.dirname(__file__))
model_path = os.path.join(base_path, "model", "model.pkl")

model = joblib.load(model_path)

# 🔐 API KEY (SET IN ENV OR DIRECTLY HERE)
import streamlit as st

ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]

# ---------------- IP INTEL ---------------- #

def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        abuse_score = data["data"]["abuseConfidenceScore"]

        if abuse_score > 80:
            return "🚨 Known Malicious IP", abuse_score
        elif abuse_score > 40:
            return "⚠️ Suspicious IP", abuse_score
        else:
            return "✅ Clean IP", abuse_score

    except:
        return "⚠️ Intel lookup failed", 0


# ---------------- MITRE MAPPING ---------------- #

def map_mitre(data):
    mitre = []

    if data.get("alert_type_Brute Force", 0):
        mitre.append("T1110 - Brute Force")

    if data.get("alert_type_Credential Stuffing", 0):
        mitre.append("T1110.004 - Credential Stuffing")

    if data.get("alert_type_Password Spray", 0):
        mitre.append("T1110.003 - Password Spray")

    if data.get("alert_type_Suspicious Activity", 0):
        mitre.append("T1059 - Command Execution")

    return mitre


# ---------------- RISK ENGINE ---------------- #

def calculate_risk_score(data, ip_score):
    score = 0
    reasons = []

    # 🔥 Failed logins weight
    if data.get("failed_logins", 0) > 20:
        score += 40
        reasons.append("Extremely high failed login attempts")
    elif data.get("failed_logins", 0) > 10:
        score += 25
        reasons.append("High failed login attempts")

    # 🔥 Attack types
    if data.get("alert_type_Brute Force", 0):
        score += 30
        reasons.append("Brute force attack detected")

    if data.get("alert_type_Credential Stuffing", 0):
        score += 35
        reasons.append("Credential stuffing pattern")

    if data.get("alert_type_Password Spray", 0):
        score += 25
        reasons.append("Password spray attack")

    if data.get("alert_type_Suspicious Activity", 0):
        score += 20
        reasons.append("Suspicious process activity")

    # 🌍 Geo risk
    if data.get("location_Russia", 0):
        score += 15
        reasons.append("Login from Russia (high-risk region)")

    if data.get("location_China", 0):
        score += 10
        reasons.append("Login from China")

    if data.get("location_North Korea", 0):
        score += 20
        reasons.append("Login from North Korea")

    # 🌐 IP reputation
    score += int(ip_score * 0.5)

    return min(score, 100), reasons


# ---------------- MAIN PREDICTION ---------------- #

def predict_alert(data, ip="8.8.8.8"):
    df = pd.DataFrame([data])

    # 🔥 Align features
    expected_columns = model.feature_names_in_

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[expected_columns]

    prediction = model.predict(df)[0]

    # 🌐 IP INTEL
    ip_status, ip_score = check_ip_reputation(ip)

    # 🧠 Risk
    risk_score, reasons = calculate_risk_score(data, ip_score)

    # 🎯 MITRE
    mitre = map_mitre(data)

    # 🚨 Severity
    if risk_score > 80:
        severity = "🔴 Critical"
    elif risk_score > 60:
        severity = "🟠 High"
    elif risk_score > 30:
        severity = "🟡 Medium"
    else:
        severity = "🟢 Low"

    # 🔍 Behavior analysis
    if data.get("failed_logins", 0) > 15:
        anomaly = "⚠️ Anomalous Behavior Detected"
    else:
        anomaly = "Normal"

    # 📢 Final result
    if prediction == 1:
        result = "🚨 Threat Detected"
    else:
        result = "✅ Benign Activity"

    return result, risk_score, severity, mitre, anomaly, ip_status