import streamlit as st
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import predict_alert

st.set_page_config(page_title="SOC Dashboard", layout="wide")

st.title("🛡️ SOC AI Threat Intelligence Dashboard")

col1, col2 = st.columns(2)

with col1:
    failed_logins = st.slider("Failed Logins", 0, 50)
    ip = st.text_input("Source IP", "192.168.1.1")

with col2:
    location = st.selectbox("Location", ["India","US","Russia","China","North Korea"])
    alert_type = st.selectbox("Attack Type", [
        "Normal Login","Brute Force","Credential Stuffing","Password Spray","Suspicious Login"
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
    "alert_type_Suspicious Login": 1 if alert_type=="Suspicious Login" else 0,
}

if st.button("🚨 Analyze"):
    result, score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip)

    st.subheader("🔍 Analysis Result")
    st.write(result)

    st.metric("Risk Score", score)
    st.metric("Severity", severity)

    st.write("🌐 IP Status:", ip_status)
    st.write("🧠 Behavior:", anomaly)

    st.subheader("🎯 MITRE ATT&CK Techniques")
    for t in mitre:
        st.write(f"- {t}")