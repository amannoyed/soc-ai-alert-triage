import joblib
import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Base paths
base_path = os.path.dirname(os.path.dirname(__file__))
data_path = os.path.join(base_path, "data", "sample_logs.csv")
model_dir = os.path.join(base_path, "model")
model_path = os.path.join(model_dir, "model.pkl")

# 🔥 TRAIN MODEL DIRECTLY IF NOT EXISTS
def train_model():
    df = pd.read_csv(data_path)

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, model_path)

    return model

# Ensure model exists
if not os.path.exists(model_path):
    model = train_model()
else:
    model = joblib.load(model_path)

# Threat intel
malicious_ips = [
    "10.0.0.5",
    "45.33.32.1",
    "185.220.101.1",
    "103.21.244.0"
]

def check_ip(ip):
    return "⚠️ Known Malicious IP" if ip in malicious_ips else "✅ Clean IP"

def explain_alert(data):
    reasons = []

    if data["failed_logins"] > 25:
        reasons.append("Extremely high failed login attempts")
    elif data["failed_logins"] > 10:
        reasons.append("Moderate failed login attempts")

    if data.get("location_Russia", 0):
        reasons.append("Login from Russia (high-risk region)")

    if data.get("location_China", 0):
        reasons.append("Login from China (suspicious pattern)")

    if data.get("location_North Korea", 0):
        reasons.append("Login from North Korea (critical alert)")

    if data.get("alert_type_Brute Force", 0):
        reasons.append("Brute force attack detected")

    if data.get("alert_type_Credential Stuffing", 0):
        reasons.append("Credential stuffing behavior detected")

    if data.get("alert_type_Password Spray", 0):
        reasons.append("Password spray attack pattern")

    if data.get("alert_type_Suspicious Login", 0):
        reasons.append("Unusual login behavior")

    if not reasons:
        reasons.append("Normal login behavior")

    return " | ".join(reasons)

def predict_alert(data, ip="192.168.1.1"):
    df = pd.DataFrame([data])

    expected_columns = model.feature_names_in_

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[expected_columns]

    prediction = model.predict(df)[0]

    severity = "Low"

    if data["failed_logins"] > 25:
        severity = "Critical"
    elif data["failed_logins"] > 15:
        severity = "High"
    elif data["failed_logins"] > 8:
        severity = "Medium"

    if data.get("location_North Korea", 0):
        severity = "Critical"

    if data.get("alert_type_Credential Stuffing", 0):
        severity = "High"

    ip_status = check_ip(ip)
    explanation = explain_alert(data)

    result = (
        f"🚨 Threat Detected ({severity} Severity)"
        if prediction == 1
        else f"✅ Benign Activity ({severity} Risk)"
    )

    return result, ip_status, explanation