import joblib
import pandas as pd
import os

# Load model
base_path = os.path.dirname(os.path.dirname(__file__))
model_path = os.path.join(base_path, "model", "model.pkl")

model = joblib.load(model_path)

# 🔥 Expanded Threat Intelligence
malicious_ips = [
    "10.0.0.5",
    "45.33.32.1",
    "185.220.101.1",
    "103.21.244.0"
]

def check_ip(ip):
    if ip in malicious_ips:
        return "⚠️ Known Malicious IP"
    return "✅ Clean IP"

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

    # Ensure all expected columns exist (MODEL SAFE)
    expected_columns = model.feature_names_in_

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    df = df[expected_columns]

    prediction = model.predict(df)[0]

    # 🔥 Advanced severity logic
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

    if prediction == 1:
        result = f"🚨 Threat Detected ({severity} Severity)"
    else:
        result = f"✅ Benign Activity ({severity} Risk)"

    return result, ip_status, explanation


# 🔥 TEST BLOCK
if __name__ == "__main__":
    test_data = {
        "failed_logins": 30,

        # Locations
        "location_India": 0,
        "location_Russia": 1,
        "location_US": 0,
        "location_China": 0,
        "location_Germany": 0,
        "location_Brazil": 0,
        "location_UK": 0,
        "location_North Korea": 0,

        # Devices
        "device_Windows": 0,
        "device_Linux": 1,

        # Attack types
        "alert_type_Brute Force": 1,
        "alert_type_Normal Login": 0,
        "alert_type_Credential Stuffing": 0,
        "alert_type_Password Spray": 0,
        "alert_type_Suspicious Login": 0,
    }

    result, ip_status, explanation = predict_alert(test_data, "10.0.0.5")

    print(result)
    print(ip_status)
    print("Reason:", explanation)