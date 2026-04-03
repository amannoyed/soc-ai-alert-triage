from correlation_engine import correlate_events
import streamlit as st
import sys
import os

# 🔥 Fix import paths
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import predict_alert
from log_parser import parse_evtx

st.set_page_config(page_title="SOC Dashboard", layout="wide")

st.title("🛡️ SOC AI Threat Intelligence Dashboard")

# ---------------- MANUAL INPUT ---------------- #

st.header("🔧 Manual Alert Simulation")

col1, col2 = st.columns(2)

with col1:
    failed_logins = st.slider("Failed Logins", 0, 50)
    ip = st.text_input("Source IP", "8.8.8.8")

with col2:
    location = st.selectbox("Location", ["India","US","Russia","China","North Korea"])
    alert_type = st.selectbox("Attack Type", [
        "Normal Login","Brute Force","Credential Stuffing","Password Spray","Suspicious Activity"
    ])

input_data = {
    "failed_logins": failed_logins,
    "location_India": 1 if location=="India" else 0,
    "location_US": 1 if location=="US" else 0,
    "location_Russia": 1 if location=="Russia" else 0,
    "location_China": 1 if location=="China" else 0,
    "location_North Korea": 1 if location=="North Korea" else 0,
    "alert_type_Normal Login": 1 if alert_type=="Normal Login" else 0,
    "alert_type_Brute Force": 1 if alert_type=="Brute Force" else 0,
    "alert_type_Credential Stuffing": 1 if alert_type=="Credential Stuffing" else 0,
    "alert_type_Password Spray": 1 if alert_type=="Password Spray" else 0,
    "alert_type_Suspicious Activity": 1 if alert_type=="Suspicious Activity" else 0,
}

if st.button("🚨 Analyze Manual Input"):
    result, score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip)

    st.subheader("🔍 Result")
    st.write(result)

    col1, col2 = st.columns(2)
    col1.metric("Risk Score", score)
    col2.metric("Severity", severity)

    st.write("🌐 IP Status:", ip_status)
    st.write("🧠 Behavior:", anomaly)

    st.subheader("🎯 MITRE ATT&CK")
    for t in mitre:
        st.write(f"- {t}")

# ---------------- LOG INGESTION ---------------- #

st.header("📂 Upload EVTX Logs (Real SOC Data)")

uploaded_file = st.file_uploader("Upload Windows EVTX Log File", type=["evtx"])

if uploaded_file:
    with open("temp.evtx", "wb") as f:
        f.write(uploaded_file.read())

    parsed_logs = parse_evtx("temp.evtx")

    alerts = correlate_events(parsed_logs)

st.subheader("🧠 Correlated Threat Detection")

for alert in alerts:
    st.write(f"🚨 {alert['type']} ({alert['severity']})")
    st.write(alert["description"])
    st.write("---")

    st.success(f"Parsed {len(parsed_logs)} events")

    st.subheader("📊 Log Analysis")

    for i, log in enumerate(parsed_logs[:10]):  # show first 10 logs
        st.write(f"--- Event {i+1} ---")

        input_data = {
            "failed_logins": log["failed_logins"],
            "alert_type_Brute Force": 1 if log["alert_type"]=="Brute Force" else 0,
            "alert_type_Suspicious Activity": 1 if log["alert_type"]=="Suspicious Activity" else 0,
        }

        result, score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip="8.8.8.8")

        st.write(result)
        st.write(f"Risk Score: {score} | Severity: {severity}")
        st.write(f"Behavior: {anomaly}")
        st.write("---")