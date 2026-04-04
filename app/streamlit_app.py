import streamlit as st
import sys
import os
import matplotlib.pyplot as plt

# 🔥 Fix import paths
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import predict_alert
from log_parser import parse_evtx
from correlation_engine import correlate_events

st.set_page_config(page_title="SOC Dashboard", layout="wide")

# ---------------- 🔥 DARK SOC THEME ---------------- #

st.markdown("""
<style>
body {
    background-color: #0E1117;
}
.block-container {
    padding-top: 2rem;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SOC AI Threat Intelligence Dashboard")

# ---------------- 🔥 KPI PANEL ---------------- #

st.markdown("### 🚨 SOC Overview")

k1, k2, k3, k4 = st.columns(4)

k1.metric("Alerts Today", "128")
k2.metric("Critical Threats", "7")
k3.metric("Suspicious IPs", "23")
k4.metric("System Status", "Active")

# ---------------- 🔧 MANUAL INPUT ---------------- #

st.markdown("### 🔧 Manual Simulation")

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

if st.button("🚨 Analyze"):
    result, score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip)

    st.markdown("### 🔍 Detection Result")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk Score", score)
    c2.metric("Severity", severity)
    c3.metric("IP Status", ip_status)

    st.write("🧠 Behavior:", anomaly)

    st.markdown("#### 🎯 MITRE Mapping")
    for t in mitre:
        st.write(f"- {t}")

# ---------------- 📂 LOG INGESTION ---------------- #

st.markdown("### 📂 Log Ingestion")

uploaded_file = st.file_uploader("Upload EVTX File", type=["evtx"])

if uploaded_file:
    with open("temp.evtx", "wb") as f:
        f.write(uploaded_file.read())

    parsed_logs = parse_evtx("temp.evtx")

    st.success(f"Parsed {len(parsed_logs)} events")

    # ---------------- 🧠 CORRELATION ---------------- #
    st.markdown("### 🧠 Correlated Threats")

    alerts = correlate_events(parsed_logs)

    for alert in alerts:
        st.error(f"{alert['type']} ({alert['severity']})")
        st.write(alert["description"])

    # ---------------- 📈 TIMELINE ---------------- #
    st.markdown("### 📈 Attack Timeline")

    severity_map = {
        "Normal Login": 1,
        "Suspicious Activity": 3,
        "Brute Force": 5,
        "Privilege Escalation": 8
    }

    y = [severity_map.get(log.get("alert_type", "Normal Login"), 1) for log in parsed_logs[:20]]
    x = list(range(len(y)))

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(x, y, marker='o')

    ax.set_yticks([1, 3, 5, 8])
    ax.set_yticklabels(["Normal", "Suspicious", "Brute Force", "Priv Esc"])

    ax.set_title("Attack Progression")
    ax.set_xlabel("Event Sequence")
    ax.set_ylabel("Threat Level")

    # Dark theme fix
    fig.patch.set_facecolor('#0E1117')
    ax.set_facecolor('#0E1117')
    ax.tick_params(colors='white')
    ax.title.set_color('white')
    ax.xaxis.label.set_color('white')
    ax.yaxis.label.set_color('white')

    st.pyplot(fig)

    # ---------------- 📊 EVENT ANALYSIS ---------------- #
    st.markdown("### 📊 Event Analysis")

    for i, log in enumerate(parsed_logs[:10]):

        st.markdown(f"**Event {i+1}**")

        input_data = {
            "failed_logins": log.get("failed_logins", 0),
            "alert_type_Normal Login": 1 if log.get("alert_type") == "Normal Login" else 0,
            "alert_type_Brute Force": 1 if log.get("alert_type") == "Brute Force" else 0,
            "alert_type_Credential Stuffing": 1 if log.get("alert_type") == "Credential Stuffing" else 0,
            "alert_type_Password Spray": 1 if log.get("alert_type") == "Password Spray" else 0,
            "alert_type_Suspicious Activity": 1 if log.get("alert_type") == "Suspicious Activity" else 0,
        }

        real_ip = log.get("source_ip", "8.8.8.8")

        result, score, severity, mitre, anomaly, ip_status = predict_alert(
            input_data,
            ip=real_ip
        )

        c1, c2, c3 = st.columns(3)
        c1.write(f"🌐 IP: {real_ip}")
        c2.write(f"Risk: {score}")
        c3.write(f"Severity: {severity}")

        st.write(result)
        st.write("---")