import streamlit as st
import sys
import os
import matplotlib.pyplot as plt

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import predict_alert

# 🔥 Auto-train model if missing
base_path = os.path.dirname(os.path.dirname(__file__))
model_path = os.path.join(base_path, "model", "model.pkl")

if not os.path.exists(model_path):
    os.system("python ../src/train_model.py")

st.set_page_config(page_title="SOC AI Dashboard", layout="centered")

st.title("🚨 AI-Powered SOC Alert Triage System")
st.write("Simulate and analyze security alerts using AI")

# Inputs
failed_logins = st.slider("Failed Login Attempts", 0, 50, 5)
ip = st.text_input("Source IP Address", "192.168.1.1")

# 🌍 Location
location = st.selectbox(
    "Location",
    ["India", "US", "Russia", "China", "Germany", "Brazil", "UK", "North Korea"]
)

# 💻 Operating Systems (NEW 🔥)
device = st.selectbox(
    "Operating System",
    ["Windows", "Linux", "MacOS", "Android", "iOS"]
)

# ⚔️ Attack Types
alert_type = st.selectbox(
    "Attack Type",
    [
        "Normal Login",
        "Brute Force",
        "Credential Stuffing",
        "Password Spray",
        "Suspicious Login"
    ]
)

# Convert input
input_data = {
    "failed_logins": failed_logins,

    # Locations
    "location_India": 1 if location == "India" else 0,
    "location_US": 1 if location == "US" else 0,
    "location_Russia": 1 if location == "Russia" else 0,
    "location_China": 1 if location == "China" else 0,
    "location_Germany": 1 if location == "Germany" else 0,
    "location_Brazil": 1 if location == "Brazil" else 0,
    "location_UK": 1 if location == "UK" else 0,
    "location_North Korea": 1 if location == "North Korea" else 0,

    # Devices
    "device_Windows": 1 if device == "Windows" else 0,
    "device_Linux": 1 if device == "Linux" else 0,
    "device_MacOS": 1 if device == "MacOS" else 0,
    "device_Android": 1 if device == "Android" else 0,
    "device_iOS": 1 if device == "iOS" else 0,

    # Attack Types
    "alert_type_Normal Login": 1 if alert_type == "Normal Login" else 0,
    "alert_type_Brute Force": 1 if alert_type == "Brute Force" else 0,
    "alert_type_Credential Stuffing": 1 if alert_type == "Credential Stuffing" else 0,
    "alert_type_Password Spray": 1 if alert_type == "Password Spray" else 0,
    "alert_type_Suspicious Login": 1 if alert_type == "Suspicious Login" else 0,
}

# Analyze
if st.button("🔍 Analyze Alert"):
    result, ip_status, explanation = predict_alert(input_data, ip)

    if "Threat" in result:
        st.error(result)
    else:
        st.success(result)

    st.info(ip_status)
    st.warning("🧠 Reason: " + explanation)

    # Chart
    st.subheader("📊 Activity Breakdown")

    normal = max(0, 50 - failed_logins)
    data = [failed_logins, normal]
    labels = ["Failed Attempts", "Normal Activity"]

    fig, ax = plt.subplots()
    ax.pie(data, labels=labels, autopct='%1.1f%%')

    st.pyplot(fig)