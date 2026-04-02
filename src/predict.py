import joblib
import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from preprocess import load_data

# Paths
base_path = os.path.dirname(os.path.dirname(__file__))
model_dir = os.path.join(base_path, "model")
model_path = os.path.join(model_dir, "model.pkl")

# 🔥 TRAIN MODEL
def train_model():
    df = load_data()

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, model_path)

    return model

if not os.path.exists(model_path):
    model = train_model()
else:
    model = joblib.load(model_path)

# 🔥 THREAT INTEL
malicious_ips = ["10.0.0.5", "45.33.32.1", "185.220.101.1"]

def check_ip(ip):
    return "⚠️ Known Malicious IP" if ip in malicious_ips else "✅ Clean IP"

# 🔥 RISK SCORING ENGINE (SOC STYLE)
def calculate_risk_score(data):
    score = 0

    # Failed logins weight
    score += data["failed_logins"] * 2

    # Location risk
    if data.get("location_Russia", 0):
        score += 20
    if data.get("location_China", 0):
        score += 25
    if data.get("location_North Korea", 0):
        score += 40

    # Attack types
    if data.get("alert_type_Brute Force", 0):
        score += 25
    if data.get("alert_type_Credential Stuffing", 0):
        score += 30
    if data.get("alert_type_Password Spray", 0):
        score += 20

    return min(score, 100)

# 🔥 SEVERITY FROM SCORE
def get_severity(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

# 🔥 MITRE ATT&CK MAPPING
def map_mitre(data):
    techniques = []

    if data.get("alert_type_Brute Force", 0):
        techniques.append("T1110 - Brute Force")

    if data.get("alert_type_Credential Stuffing", 0):
        techniques.append("T1110.004 - Credential Stuffing")

    if data.get("alert_type_Password Spray", 0):
        techniques.append("T1110.003 - Password Spraying")

    if data.get("alert_type_Suspicious Login", 0):
        techniques.append("T1078 - Valid Accounts")

    return techniques

# 🔥 ANOMALY DETECTION
def detect_anomaly(data):
    if data["failed_logins"] > 30:
        return "⚠️ Anomalous Behavior Detected"
    return "Normal Behavior"

def predict_alert(data, ip="192.168.1.1"):
    df = pd.DataFrame([data])

    expected_columns = model.feature_names_in_

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[expected_columns]

    prediction = model.predict(df)[0]

    # 🔥 SOC LOGIC
    risk_score = calculate_risk_score(data)
    severity = get_severity(risk_score)
    mitre = map_mitre(data)
    anomaly = detect_anomaly(data)
    ip_status = check_ip(ip)

    result = (
        f"🚨 Threat Detected ({severity})"
        if prediction == 1
        else f"✅ Benign Activity ({severity})"
    )

    return result, risk_score, severity, mitre, anomaly, ip_status