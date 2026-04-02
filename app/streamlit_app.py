import streamlit as st
import sys
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from predict import predict_alert

st.set_page_config(page_title="SOC AI Dashboard", layout="wide", page_icon="🛡️")

# ─── Dark SOC Theme ───────────────────────────────────────────
st.markdown("""
<style>
body { background-color: #0d1117; color: #c9d1d9; }
.stApp { background-color: #0d1117; }
.block-container { padding: 2rem 3rem; }
h1 { color: #58a6ff; font-family: monospace; }
h2, h3 { color: #8b949e; font-family: monospace; }
.stMetric { background-color: #161b22; border-radius: 10px; padding: 10px; border: 1px solid #30363d; }
.stButton > button {
    background-color: #1f6feb; color: white;
    border-radius: 6px; border: none;
    padding: 0.5em 2em; font-size: 16px;
}
.stButton > button:hover { background-color: #388bfd; }
</style>
""", unsafe_allow_html=True)

# ─── Header ───────────────────────────────────────────────────
st.title("🛡️ SOC AI Threat Intelligence Dashboard")
st.caption("AI-powered alert triage · Risk scoring · MITRE ATT&CK mapping · Anomaly detection")
st.markdown("---")

# ─── Input Panel ──────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("🔐 Login Activity")
    failed_logins = st.slider("Failed Login Attempts", 0, 50, 5)
    ip = st.text_input("Source IP Address", "192.168.1.1")

with col2:
    st.subheader("🌍 Geolocation & Device")
    location = st.selectbox("Origin Location", [
        "India", "US", "UK", "Germany", "Brazil",
        "Russia", "China", "North Korea"
    ])
    device = st.selectbox("Operating System", [
        "Windows", "Linux", "MacOS", "Android", "iOS"
    ])

with col3:
    st.subheader("⚔️ Attack Classification")
    alert_type = st.selectbox("Attack Type", [
        "Normal Login",
        "Brute Force",
        "Credential Stuffing",
        "Password Spray",
        "Suspicious Login"
    ])
    st.markdown("<br>", unsafe_allow_html=True)
    analyze = st.button("🚨 Run Threat Analysis", use_container_width=True)

# ─── Build Input Dict ─────────────────────────────────────────
input_data = {
    "failed_logins": failed_logins,
    "location_India": 1 if location == "India" else 0,
    "location_US": 1 if location == "US" else 0,
    "location_UK": 1 if location == "UK" else 0,
    "location_Germany": 1 if location == "Germany" else 0,
    "location_Brazil": 1 if location == "Brazil" else 0,
    "location_Russia": 1 if location == "Russia" else 0,
    "location_China": 1 if location == "China" else 0,
    "location_North Korea": 1 if location == "North Korea" else 0,
    "device_Windows": 1 if device == "Windows" else 0,
    "device_Linux": 1 if device == "Linux" else 0,
    "device_MacOS": 1 if device == "MacOS" else 0,
    "device_Android": 1 if device == "Android" else 0,
    "device_iOS": 1 if device == "iOS" else 0,
    "alert_type_Normal Login": 1 if alert_type == "Normal Login" else 0,
    "alert_type_Brute Force": 1 if alert_type == "Brute Force" else 0,
    "alert_type_Credential Stuffing": 1 if alert_type == "Credential Stuffing" else 0,
    "alert_type_Password Spray": 1 if alert_type == "Password Spray" else 0,
    "alert_type_Suspicious Login": 1 if alert_type == "Suspicious Login" else 0,
}

# ─── Analysis Output ──────────────────────────────────────────
if analyze:
    result, risk_score, severity, mitre, anomaly, ip_status = predict_alert(input_data, ip)

    st.markdown("---")
    st.subheader("📊 Threat Analysis Report")

    # Top metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🎯 Risk Score", f"{risk_score} / 100")
    m2.metric("⚠️ Severity", severity)
    m3.metric("🌐 IP Intel", "Malicious" if "Malicious" in ip_status else "Clean")
    m4.metric("🧠 Behaviour", "Anomalous" if "Anomalous" in anomaly else "Normal")

    # Alert banner
    if "Threat" in result:
        st.error(f"🚨 {result}")
    else:
        st.success(f"✅ {result}")

    st.info(f"🌐 IP Status: {ip_status}")
    st.warning(f"🧠 Anomaly Check: {anomaly}")

    # MITRE ATT&CK
    st.markdown("---")
    st.subheader("🎯 MITRE ATT&CK Techniques")
    if mitre:
        for t in mitre:
            st.markdown(f"&nbsp;&nbsp;🔴 `{t}`", unsafe_allow_html=True)
    else:
        st.markdown("&nbsp;&nbsp;✅ No known attack techniques mapped", unsafe_allow_html=True)

    # Risk gauge + breakdown
    st.markdown("---")
    st.subheader("📈 Risk Breakdown")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        # Risk gauge (simple bar)
        fig, ax = plt.subplots(figsize=(5, 1.2))
        fig.patch.set_facecolor('#161b22')
        ax.set_facecolor('#161b22')
        color = "#ff4444" if risk_score >= 80 else "#ffaa00" if risk_score >= 50 else "#44ff88"
        ax.barh(["Risk"], [risk_score], color=color, height=0.4)
        ax.barh(["Risk"], [100 - risk_score], left=risk_score, color="#30363d", height=0.4)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Risk Score", color="#8b949e")
        ax.tick_params(colors="#8b949e")
        for spine in ax.spines.values():
            spine.set_edgecolor('#30363d')
        ax.set_title(f"Risk Score: {risk_score}/100", color="#58a6ff", fontsize=11)
        st.pyplot(fig)

    with chart_col2:
        # Pie chart of failed vs normal
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

    # Response recommendations
    st.markdown("---")
    st.subheader("🛠️ Recommended Response Actions")
    if severity in ["Critical", "High"]:
        st.markdown("""
        - 🔴 **Block source IP immediately**
        - 🔴 **Disable affected account**
        - 🟠 **Escalate to Tier 2 analyst**
        - 🟠 **Initiate incident response playbook**
        - 🟡 **Collect forensic logs from endpoint**
        """)
    elif severity == "Medium":
        st.markdown("""
        - 🟡 **Flag account for monitoring**
        - 🟡 **Force password reset on next login**
        - 🟢 **Log event in SIEM for correlation**
        """)
    else:
        st.markdown("""
        - 🟢 **No immediate action required**
        - 🟢 **Continue baseline monitoring**
        """)

st.markdown("---")
st.caption("Built with Python · Scikit-learn · Streamlit | Portfolio Project by Aman Ali")
```

---

**Key upgrades in this version:**

The UI now has a dark SOC console theme, a 3-column input panel, a live risk gauge bar, a login activity pie chart, and a **Response Actions** section that tells the analyst exactly what to do — which is what real SOC tools like Splunk ES and Microsoft Sentinel actually show.

**Your `predict.py` stays the same** from the last working version (the advanced SOC version ChatGPT gave you — don't change it).

---

**After updating the file:**

1. Upload the new `streamlit_app.py` to GitHub (overwrite the old one)
2. Go to your Streamlit app → click **Reboot app**
3. You'll have a proper dark-themed SOC dashboard

---

**One more thing — add this to your `requirements.txt`** to make sure everything deploys cleanly:
```
pandas
scikit-learn
streamlit
joblib
matplotlib
numpy