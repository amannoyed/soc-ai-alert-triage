import streamlit as st
import sys
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import predict_alert, check_ip_reputation
from log_parser import parse_evtx
from correlation_engine import correlate_events
from kill_chain import map_kill_chain

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stSidebar"] { background-color: #0d1117; }
.block-container { padding-top: 1.5rem; padding-bottom: 1rem; }
.stMetric { background-color: #161b22; border: 1px solid #30363d;
             border-radius: 8px; padding: 12px; }
.stAlert  { border-radius: 6px; }
div[data-testid="stExpander"] { border: 1px solid #30363d; border-radius: 6px; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ SOC AI Platform")
    st.caption("v2.0 — Threat Intelligence Dashboard")
    st.divider()

    st.subheader("⚙️ Settings")
    auto_refresh = st.checkbox("🔄 Auto-Refresh (Live Mode)")
    refresh_rate = st.slider("Refresh interval (sec)", 5, 60, 15)

    st.divider()
    st.subheader("🔗 Quick Links")
    st.markdown("- [MITRE ATT&CK](https://attack.mitre.org)")
    st.markdown("- [AbuseIPDB](https://www.abuseipdb.com)")
    st.markdown("- [VirusTotal](https://www.virustotal.com)")
    st.markdown("- [Shodan](https://www.shodan.io)")
    st.markdown("- [Greynoise](https://greynoise.io)")

    st.divider()
    st.caption("Built for SOC operations · Powered by ML + MITRE ATT&CK")

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ SOC AI Threat Intelligence Dashboard")
st.caption("AI-powered alert triage · MITRE ATT&CK mapping · Real-time log analysis")

# ── KPI Row ───────────────────────────────────────────────────────────────────
st.markdown("---")
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("🚨 Alerts Today",    "147", "+12")
k2.metric("🔴 Critical",        "9",   "+3")
k3.metric("🟠 High",            "23",  "+5")
k4.metric("⚠️ Suspicious IPs", "31",  "+8")
k5.metric("✅ System Status",   "Active")
st.markdown("---")

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["🔧 Manual Simulation", "📂 Log Analysis", "📊 Threat Intel"])


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — MANUAL SIMULATION
# ═══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Manual Alert Simulation")
    st.caption("Simulate a security event and analyze it in real-time.")

    c1, c2, c3 = st.columns(3)

    with c1:
        failed_logins = st.slider("Failed Login Attempts", 0, 50, 5)
        ip = st.text_input("Source IP Address", "8.8.8.8")

    with c2:
        location = st.selectbox("Origin Country", [
            "India", "US", "UK", "Germany", "Brazil",
            "Russia", "China", "North Korea"
        ])
        device = st.selectbox("Operating System", [
            "Windows", "Linux", "MacOS", "Android", "iOS"
        ])

    with c3:
        alert_type = st.selectbox("Alert / Attack Type", [
            "Normal Login",
            "Brute Force",
            "Credential Stuffing",
            "Password Spray",
            "Suspicious Login",
            "Suspicious Activity",
            "Malware Execution",
            "Privilege Escalation",
            "Credential Dumping",
        ])
        time_of_day = st.selectbox("Time of Day", [
            "Business Hours (9–17)",
            "Evening (17–22)",
            "Night (22–6)",
            "Early Morning (6–9)"
        ])

    input_data = {
        "failed_logins": failed_logins,
        "location_India":       1 if location == "India"       else 0,
        "location_US":          1 if location == "US"          else 0,
        "location_UK":          1 if location == "UK"          else 0,
        "location_Germany":     1 if location == "Germany"     else 0,
        "location_Brazil":      1 if location == "Brazil"      else 0,
        "location_Russia":      1 if location == "Russia"      else 0,
        "location_China":       1 if location == "China"       else 0,
        "location_North Korea": 1 if location == "North Korea" else 0,
        "device_Windows": 1 if device == "Windows" else 0,
        "device_Linux":   1 if device == "Linux"   else 0,
        "device_MacOS":   1 if device == "MacOS"   else 0,
        "device_Android": 1 if device == "Android" else 0,
        "device_iOS":     1 if device == "iOS"     else 0,
        "alert_type_Normal Login":        1 if alert_type == "Normal Login"        else 0,
        "alert_type_Brute Force":         1 if alert_type == "Brute Force"         else 0,
        "alert_type_Credential Stuffing": 1 if alert_type == "Credential Stuffing" else 0,
        "alert_type_Password Spray":      1 if alert_type == "Password Spray"      else 0,
        "alert_type_Suspicious Login":    1 if alert_type == "Suspicious Login"    else 0,
    }

    if st.button("🚨 Run Analysis", type="primary", use_container_width=True):
        with st.spinner("Analyzing..."):
            result, score, severity, mitre, anomaly, ip_status, reasons = predict_alert(
                input_data, ip
            )

        st.markdown("---")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Risk Score", f"{score}/100")
        r2.metric("Severity",   severity)
        r3.metric("ML Result",  "Threat" if "Threat" in result else "Benign")
        r4.metric("IP Status",  ip_status[:20] + "..." if len(ip_status) > 20 else ip_status)

        col_left, col_right = st.columns(2)

        with col_left:
            if "Threat" in result:
                st.error(f"**{result}**")
            else:
                st.success(f"**{result}**")

            st.info(f"🌐 **IP Intelligence:** {ip_status}")
            st.warning(f"🧠 **Behavior:** {anomaly}")

            if reasons:
                st.markdown("**📋 Detection Reasons:**")
                for r in reasons:
                    st.markdown(f"  - {r}")

        with col_right:
            st.markdown("**🎯 MITRE ATT&CK Techniques:**")
            if mitre:
                for m in mitre:
                    st.code(m, language=None)
            else:
                st.markdown("_No specific techniques mapped for this alert type_")

            # Risk gauge bar
            fig, ax = plt.subplots(figsize=(4, 1.8))
            bar_color = "#2ea043" if score < 35 else "#d29922" if score < 60 else "#f85149"
            ax.barh(["Risk"], [score],       color=bar_color, height=0.4)
            ax.barh(["Risk"], [100 - score], left=[score], color="#21262d", height=0.4)
            ax.set_xlim(0, 100)
            ax.set_xticks([0, 35, 60, 80, 100])
            ax.set_xticklabels(["0", "Low", "Med", "High", "100"],
                               color="white", fontsize=8)
            ax.tick_params(axis="y", colors="white")
            ax.set_facecolor("#0d1117")
            fig.patch.set_facecolor("#0d1117")
            ax.set_title(f"Risk Score: {score}/100", color="white", fontsize=9)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["bottom"].set_color("#30363d")
            ax.spines["left"].set_color("#30363d")
            st.pyplot(fig)
            plt.close()

        # Recommended actions
        st.markdown("---")
        st.markdown("**🛡️ Recommended Response Actions:**")
        if score >= 80:
            st.error("""
**CRITICAL — Immediate action required:**
1. Block source IP at firewall
2. Isolate affected endpoint
3. Reset compromised credentials
4. Escalate to Tier 2 / Incident Response
5. Preserve logs and open incident ticket
            """)
        elif score >= 60:
            st.warning("""
**HIGH — Respond within 1 hour:**
1. Add IP to watchlist / rate limit
2. Review authentication logs for this user
3. Check for lateral movement indicators
4. Alert asset owner
            """)
        elif score >= 35:
            st.warning("""
**MEDIUM — Investigate within 4 hours:**
1. Monitor IP for continued activity
2. Review user behavior baseline
3. Check for related alerts
            """)
        else:
            st.success("""
**LOW — Standard monitoring:**
1. Log event for audit trail
2. No immediate action required
            """)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — LOG ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("EVTX Log Analysis")
    st.caption(
        "Upload Windows Event Log (.evtx) files for automated SOC analysis. "
        "Supports Security logs, Sysmon logs, and System logs."
    )

    uploaded_file = st.file_uploader(
        "Upload EVTX Log File",
        type=["evtx"],
        help="Max 200MB. Supports Security, Sysmon, Application event logs."
    )

    if not uploaded_file:
        st.info("📂 Upload an EVTX file to begin log analysis.")
        st.markdown("""
**Supported log types:**
- `Security.evtx` — Login events, privilege changes (Event IDs: 4624, 4625, 4672)
- `Sysmon.evtx` — Process creation, network connections (Event IDs: 1, 3, 10)
- `System.evtx` — Service changes, driver loads

**How to export logs on Windows:**
```
Event Viewer → Windows Logs → Security → Save All Events As...
```

**Or use this PowerShell command:**
```powershell
wevtutil epl Security C:\\Users\\YourName\\security_logs.evtx
```
        """)

    else:
        # Save uploaded file
        with open("temp_analysis.evtx", "wb") as f:
            f.write(uploaded_file.read())

        with st.spinner("Parsing log file and running AI analysis..."):
            parsed_logs = parse_evtx("temp_analysis.evtx")

        st.success(f"✅ Parsed **{len(parsed_logs)} events** from `{uploaded_file.name}`")

        # ── Summary Stats ─────────────────────────────────────────────────────
        threat_events  = [l for l in parsed_logs if l["alert_type"] != "Normal Login"]
        normal_events  = [l for l in parsed_logs if l["alert_type"] == "Normal Login"]
        unique_ips     = len({l["source_ip"] for l in parsed_logs})
        threat_ips     = len({l["source_ip"] for l in threat_events})

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Events",    len(parsed_logs))
        s2.metric("Threat Events",   len(threat_events),
                  delta=f"{len(threat_events)} flagged",
                  delta_color="inverse")
        s3.metric("Normal Events",   len(normal_events))
        s4.metric("Unique IPs",      unique_ips,
                  delta=f"{threat_ips} threat IPs",
                  delta_color="inverse")

        st.markdown("---")

        # ── Live Alert Feed ───────────────────────────────────────────────────
        st.markdown("### 🔴 Live Alert Feed (Last 5 Events)")

        recent = parsed_logs[-5:]
        for log in recent:
            d = {
                "failed_logins":                   log["failed_logins"],
                f"alert_type_{log['alert_type']}": 1,
            }
            r, sc, sev, _, _, ip_st, _ = predict_alert(d, log["source_ip"])

            if "Threat" in r:
                st.error(
                    f"🚨 **{log['alert_type']}** | "
                    f"IP: `{log['source_ip']}` | "
                    f"Event: `{log.get('event_id', '?')}` | "
                    f"Risk: **{sc}/100** | {sev}"
                )
            else:
                st.success(
                    f"✅ **{log['alert_type']}** | "
                    f"IP: `{log['source_ip']}` | "
                    f"Event: `{log.get('event_id', '?')}` | "
                    f"Risk: **{sc}/100** | {sev}"
                )

        st.markdown("---")

        # ── Two-column section: Correlation + Kill Chain ──────────────────────
        left_col, right_col = st.columns(2)

        with left_col:
            st.markdown("### 🧠 Correlated Threat Analysis")

            alerts = correlate_events(parsed_logs)

            for alert in alerts:
                sev = alert["severity"]
                if sev == "Critical":
                    st.error(
                        f"**🔴 {alert['type']}** *(Critical)*\n\n"
                        f"{alert['description']}"
                    )
                elif sev == "High":
                    st.warning(
                        f"**🟠 {alert['type']}** *(High)*\n\n"
                        f"{alert['description']}"
                    )
                elif sev == "Medium":
                    st.warning(
                        f"**🟡 {alert['type']}** *(Medium)*\n\n"
                        f"{alert['description']}"
                    )
                else:
                    st.info(
                        f"**🟢 {alert['type']}** *(Low)*\n\n"
                        f"{alert['description']}"
                    )

        with right_col:
            st.markdown("### 🧬 MITRE ATT&CK Kill Chain")

            stages = map_kill_chain(parsed_logs)

            if stages:
                confirmed = [s for s in stages if not s["inferred"]]
                inferred  = [s for s in stages if s["inferred"]]

                for s in confirmed:
                    types_str = ", ".join(s["alert_types"])
                    st.markdown(
                        f"🔴 **{s['stage']}** "
                        f"*(confirmed · {s['evidence_count']} events)*\n\n"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;`{types_str}`"
                    )

                if inferred:
                    st.markdown("---")
                    st.caption("Inferred stages (based on attack pattern):")
                    for s in inferred:
                        st.markdown(f"🔘 *{s['stage']}* *(inferred)*")

                coverage = len(confirmed)
                total    = 6
                st.progress(
                    min(coverage / total, 1.0),
                    text=f"Kill chain coverage: {coverage}/{total} confirmed stages"
                )
            else:
                st.info("No kill chain stages detected in these logs.")

        st.markdown("---")

        # ── Attack Timeline ───────────────────────────────────────────────────
        st.markdown("### 📈 Attack Progression Timeline")

        severity_num = {
            "Normal Login":        1,
            "Suspicious Login":    2,
            "Suspicious Activity": 3,
            "Password Spray":      4,
            "Credential Stuffing": 5,
            "Brute Force":         6,
            "Malware Execution":   7,
            "Privilege Escalation":8,
            "Credential Dumping":  9,
        }

        color_map = {
            1: "#2ea043", 2: "#56d364", 3: "#e3b341",
            4: "#d29922", 5: "#f0883e", 6: "#f85149",
            7: "#da3633", 8: "#b91c1c", 9: "#7f1d1d",
        }

        y_vals = [severity_num.get(l["alert_type"], 1) for l in parsed_logs]
        x_vals = list(range(len(y_vals)))
        colors = [color_map.get(v, "#2ea043") for v in y_vals]

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(x_vals, y_vals, color="#58a6ff", linewidth=1.5, alpha=0.4)
        ax.scatter(x_vals, y_vals, c=colors, s=80, zorder=5)

        ax.set_yticks([1, 2, 3, 4, 5, 6, 7, 8, 9])
        ax.set_yticklabels([
            "Normal", "Susp.Login", "Susp.Activity",
            "Pwd Spray", "Cred.Stuff", "Brute Force",
            "Malware", "PrivEsc", "Cred.Dump"
        ], fontsize=8)

        ax.set_xlabel("Event Sequence", color="white")
        ax.set_ylabel("Threat Level",   color="white")
        ax.set_title("Attack Progression (each dot = one event, color = severity)",
                     color="white")

        ax.set_facecolor("#0d1117")
        fig.patch.set_facecolor("#0d1117")
        ax.tick_params(colors="white")
        ax.spines["bottom"].set_color("#30363d")
        ax.spines["left"].set_color("#30363d")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        patches = [
            mpatches.Patch(color="#2ea043", label="Normal"),
            mpatches.Patch(color="#e3b341", label="Suspicious"),
            mpatches.Patch(color="#f0883e", label="High Risk"),
            mpatches.Patch(color="#da3633", label="Malware"),
            mpatches.Patch(color="#7f1d1d", label="Critical"),
        ]
        ax.legend(handles=patches, loc="upper left",
                  facecolor="#161b22", edgecolor="#30363d",
                  labelcolor="white", fontsize=8)

        st.pyplot(fig)
        plt.close()

        st.markdown("---")

        # ── Detailed Event Table ──────────────────────────────────────────────
        st.markdown("### 📊 Detailed Event Analysis")

        max_show = min(50, len(parsed_logs))
        show_n   = st.slider("Number of events to display", 5, max_show, min(10, max_show))

        # Filter options
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            show_threats_only = st.checkbox("Show threat events only", value=False)
        with filter_col2:
            min_risk = st.slider("Minimum risk score to show", 0, 100, 0)

        events_to_show = parsed_logs[:show_n]

        for i, log in enumerate(events_to_show):
            d = {
                "failed_logins":                   log["failed_logins"],
                f"alert_type_{log['alert_type']}": 1,
            }
            r, sc, sev, mitre_tags, anom, ip_st, rsns = predict_alert(
                d, log["source_ip"]
            )

            is_threat = "Threat" in r

            # Apply filters
            if show_threats_only and not is_threat:
                continue
            if sc < min_risk:
                continue

            icon   = "🚨" if is_threat else "✅"
            header = (
                f"{icon} Event {i+1} | "
                f"{log['alert_type']} | "
                f"Risk: {sc}/100 | "
                f"{sev} | "
                f"IP: {log['source_ip']}"
            )

            with st.expander(header, expanded=(is_threat and i < 3)):
                col_a, col_b, col_c = st.columns(3)
                col_a.markdown(f"**Event ID:** `{log.get('event_id', 'N/A')}`")
                col_b.markdown(f"**Source IP:** `{log['source_ip']}`")
                col_c.markdown(f"**Risk Score:** `{sc}/100`")

                col_d, col_e = st.columns(2)
                col_d.markdown(f"**IP Status:** {ip_st}")
                col_e.markdown(f"**Anomaly:** {anom}")

                if mitre_tags:
                    st.markdown("**🎯 MITRE ATT&CK Techniques:**")
                    for m in mitre_tags:
                        st.code(m, language=None)

                if rsns:
                    st.markdown("**📋 Detection Reasons:**")
                    for rsn in rsns:
                        st.markdown(f"  - {rsn}")

                # Inline response guidance
                if is_threat:
                    st.markdown("**🛡️ Suggested Response:**")
                    if sc >= 80:
                        st.error("Block IP · Isolate endpoint · Escalate immediately")
                    elif sc >= 60:
                        st.warning("Add to watchlist · Review auth logs · Alert team")
                    else:
                        st.info("Monitor · Check baseline · Log for audit")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — THREAT INTEL LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("IP Threat Intelligence Lookup")
    st.caption(
        "Real-time IP reputation checking. "
        "Uses AbuseIPDB API if configured, otherwise checks local threat list."
    )

    lookup_col1, lookup_col2 = st.columns([2, 1])

    with lookup_col1:
        lookup_ip = st.text_input(
            "Enter IP address to investigate",
            placeholder="e.g. 185.220.101.1"
        )

    with lookup_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        do_lookup = st.button("🔍 Investigate IP", type="primary", use_container_width=True)

    # Quick test IPs
    st.caption("Quick test — click to prefill:")
    q1, q2, q3, q4 = st.columns(4)
    with q1:
        if st.button("185.220.101.1 (Tor)", use_container_width=True):
            lookup_ip = "185.220.101.1"
            do_lookup = True
    with q2:
        if st.button("45.33.32.1 (Known bad)", use_container_width=True):
            lookup_ip = "45.33.32.1"
            do_lookup = True
    with q3:
        if st.button("8.8.8.8 (Google DNS)", use_container_width=True):
            lookup_ip = "8.8.8.8"
            do_lookup = True
    with q4:
        if st.button("1.1.1.1 (Cloudflare)", use_container_width=True):
            lookup_ip = "1.1.1.1"
            do_lookup = True

    if do_lookup and lookup_ip:
        with st.spinner(f"Querying threat intelligence for {lookup_ip} ..."):
            ip_status_str, ip_score = check_ip_reputation(lookup_ip)

        st.markdown("---")

        verdict = (
            "🔴 Malicious"   if ip_score >= 75 else
            "🟡 Suspicious"  if ip_score >= 30 else
            "🟢 Clean"
        )

        l1, l2, l3 = st.columns(3)
        l1.metric("IP Address",   lookup_ip)
        l2.metric("Abuse Score",  f"{ip_score}/100")
        l3.metric("Verdict",      verdict)

        st.markdown(f"**Full Status:** {ip_status_str}")
        st.markdown("---")

        # Verdict block
        if ip_score >= 75:
            st.error(f"""
**🔴 MALICIOUS IP CONFIRMED**

This IP has an abuse confidence score of **{ip_score}/100**.
It is flagged as highly malicious and should be blocked immediately.
            """)
        elif ip_score >= 30:
            st.warning(f"""
**🟡 SUSPICIOUS IP**

This IP has an abuse confidence score of **{ip_score}/100**.
It shows signs of suspicious activity. Monitor closely and consider blocking.
            """)
        else:
            st.success(f"""
**🟢 CLEAN IP**

This IP has an abuse confidence score of **{ip_score}/100**.
No significant threat indicators found in threat databases.
            """)

        # Response actions
        st.markdown("**🛡️ Recommended Actions:**")
        if ip_score >= 75:
            st.markdown("""
1. 🔴 **Block IP at firewall / WAF immediately**
2. Search all logs for historical connections from this IP
3. Check if any accounts authenticated from this IP
4. Revoke any active sessions from this IP
5. File incident report and add to permanent blocklist
6. Notify affected users if data may be compromised
            """)
        elif ip_score >= 30:
            st.markdown("""
1. 🟡 **Add IP to watchlist and monitor**
2. Enable rate limiting for this IP
3. Review recent authentication attempts
4. Check for unusual data access patterns
5. Consider temporary block if activity escalates
            """)
        else:
            st.markdown("""
1. 🟢 No immediate action required
2. Continue standard logging and monitoring
3. Re-check periodically if behavior changes
            """)

        # OSINT links
        st.markdown("---")
        st.markdown("**🌐 Investigate Further (OSINT):**")

        o1, o2, o3, o4, o5 = st.columns(5)
        o1.markdown(f"[AbuseIPDB](https://www.abuseipdb.com/check/{lookup_ip})")
        o2.markdown(f"[VirusTotal](https://www.virustotal.com/gui/ip-address/{lookup_ip})")
        o3.markdown(f"[Shodan](https://www.shodan.io/host/{lookup_ip})")
        o4.markdown(f"[IPInfo](https://ipinfo.io/{lookup_ip})")
        o5.markdown(f"[Greynoise](https://viz.greynoise.io/ip/{lookup_ip})")

    else:
        st.markdown("---")
        st.markdown("### 🌐 OSINT Resources")
        st.markdown("""
| Tool | Purpose |
|---|---|
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse reports and reputation |
| [VirusTotal](https://www.virustotal.com) | Multi-engine IP / domain / file scanning |
| [Shodan](https://www.shodan.io) | Internet-connected device intelligence |
| [Greynoise](https://greynoise.io) | Internet noise vs targeted attack classification |
| [IPInfo](https://ipinfo.io) | Geolocation, ASN, org lookup |
| [AlienVault OTX](https://otx.alienvault.com) | Open threat intelligence sharing |
| [URLScan](https://urlscan.io) | URL and domain scanning |
        """)

        st.info(
            "💡 **Tip:** Configure your AbuseIPDB API key in Streamlit Secrets "
            "(`ABUSEIPDB_API_KEY`) for live reputation scores. "
            "Without it, the system uses a local known-bad IP list."
        )
