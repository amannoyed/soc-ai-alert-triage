import streamlit as st
import sys
import os
import matplotlib.pyplot as plt

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from predict import predict_alert

st.set_page_config(page_title="SOC AI Dashboard", layout="wide", page_icon="shield")

st.markdown("""
<style>
.stApp { background-color: #0d1117; color: #c9d1d9; }
.block-container { padding: 2rem 3rem; }
h1, h2, h3 { font-family: monospace; }
h1 { color: #58a6ff; }
h2, h3 { color: #8b949e; }
.stButton > button {
    background-color: #1f6feb;
    color: white;
    border-radius: 6px;
    border: none;
    padding: 0.5em 2em;
    font-size: 16px;
    width: 100%;
}
.stButton > button:hover { background-color: #388bfd; }
div[data-testid="metric-container"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 12px;
}
</style>
""", unsafe_allow_html=True)

st.title("SOC AI Threat Intelligence Dashboard")
st.caption("AI-powered alert triage | Risk scoring | MITRE ATT&CK mapping | Anomaly detection")
st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("Login Activity")
    failed_logins = st.slider("Failed Login Attempts", 0, 50, 5)
    ip = st.text_input("Source IP Address", "192.168.1.1")

with col2:
    st.subheader("Geolocation and Device")
    location = st.selectbox("Origin Location", [
        "India", "US", "UK", "Germany", "Brazil",
        "Russia", "China", "North Korea"
    ])
    device = st.selectbox("Operating System", [
        "Windows", "Linux", "MacOS", "Android", "iOS"
    ])

with col3:
    st.subheader("Attack Classification")
    alert_type = st.selectbox("Attack Type", [
        "Normal Login",
        "Brute Force",
        "Credential Stuffing",
        "Password Spray",
        "Suspicious Login"
    ])
    st.markdown("<br><br>", unsafe_allow_html=True)
    analyze = st.button("Run Threat Analysis", use_container_width=True)

input_data = {
    "failed_logins": failed_logins,
    "location_India":       1 if location == "India" else 0,
    "location_US":          1 if location == "US" else 0,
    "location_UK":          1 if location == "UK" else 0,
    "location_Germany":     1 if location == "Germany" else 0,
    "location_Brazil":      1 if location == "Brazil" else 0,
    "location_Russia":      1 if location == "Russia" else 0,
    "location_China":       1 if location == "China" else 0,
    "location_North Korea": 1 if location == "North Korea" else 0,
    "device_Windows":       1 if device == "Windows" else 0,
    "device_Linux":         1 if device == "Linux" else 0,
    "device_MacOS":         1 if device == "MacOS" else 0,
    "device_Android":       1 if device == "Android" else 0,
    "device_iOS":           1 if device == "iOS" else 0,
    "alert_type_Normal Login":        1 if alert_type == "Normal Login" else 0,
    "alert_type_Brute Force":         1 if alert_type == "Brute Force" else 0,
    "alert_type_Credential Stuffing": 1 if alert_type == "Credential Stuffing" else 0,
    "alert_type_Password Spray":      1 if alert_type == "Password Spray" else 0,
    "alert_type_Suspicious Login":    1 if alert_type == "Suspicious Login" else 0,
}

if analyze:
    result, risk_score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip)

    st.markdown("---")
    st.subheader("Threat Analysis Report")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk Score", f"{risk_score} / 100")
    m2.metric("Severity", severity)
    m3.metric("IP Intel", "Malicious" if "Malicious" in ip_status else "Clean")
    m4.metric("Behaviour", "Anomalous" if "Anomalous" in anomaly else "Normal")

    if "Threat" in result:
        st.error(f"ALERT: {result}")
    else:
        st.success(f"OK: {result}")

    st.info(f"IP Status: {ip_status}")
    st.warning(f"Anomaly Check: {anomaly}")

    st.markdown("---")
    st.subheader("MITRE ATT&CK Techniques")
    if mitre:
        for t in mitre:
            st.code(t, language=None)
    else:
        st.success("No known attack techniques mapped")

    st.markdown("---")
    st.subheader("Risk Breakdown")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        fig, ax = plt.subplots(figsize=(5, 1.2))
        fig.patch.set_facecolor('#161b22')
        ax.set_facecolor('#161b22')
        if risk_score >= 80:
            bar_color = "#ff4444"
        elif risk_score >= 50:
            bar_color = "#ffaa00"
        else:
            bar_color = "#44ff88"
        ax.barh(["Risk"], [risk_score], color=bar_color, height=0.4)
        ax.barh(["Risk"], [100 - risk_score], left=risk_score, color="#30363d", height=0.4)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Risk Score", color="#8b949e")
        ax.tick_params(colors="#8b949e")
        for spine in ax.spines.values():
            spine.set_edgecolor('#30363d')
        ax.set_title(f"Risk Score: {risk_score}/100", color="#58a6ff", fontsize=11)
        st.pyplot(fig)
        plt.close(fig)

    with chart_col2:
        normal = max(1, 50 - failed_logins)
        fig2, ax2 = plt.subplots(figsize=(4, 3))
        fig2.patch.set_facecolor('#161b22')
        ax2.set_facecolor('#161b22')
        ax2.pie(
            [failed_logins, normal],
            labels=["Failed Logins", "Normal Activity"],
            colors=["#ff4444", "#238636"],
            autopct="%1.0f%%",
            textprops={"color": "#c9d1d9"}
        )
        ax2.set_title("Login Activity Split", color="#58a6ff")
        st.pyplot(fig2)
        plt.close(fig2)

    st.markdown("---")
    st.subheader("Recommended Response Actions")
    if severity in ["Critical", "High"]:
        st.markdown("""
- **Block source IP immediately**
- **Disable affected account**
- **Escalate to Tier 2 analyst**
- **Initiate incident response playbook**
- **Collect forensic logs from endpoint**
        """)
    elif severity == "Medium":
        st.markdown("""
- **Flag account for monitoring**
- **Force password reset on next login**
- **Log event in SIEM for correlation**
        """)
    else:
        st.markdown("""
- **No immediate action required**
- **Continue baseline monitoring**
        """)

st.markdown("---")
st.caption("Built with Python | Scikit-learn | Streamlit | Portfolio Project by Aman Ali")
