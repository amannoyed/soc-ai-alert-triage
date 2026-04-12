"""
app/streamlit_app.py
════════════════════
SOC AI Platform — Production Dashboard v3.1

Fixes vs v3.0:
  - Sidebar widgets now INSIDE with st.sidebar: block (were leaking into main page)
  - Import path set BEFORE any src imports (fixes Streamlit Cloud startup crash)
  - All imports wrapped in try/except with a clear human-readable error gate
  - ioc.type / ioc.value / ioc.note accessed safely (works for both dataclass and dict)
  - Unique Streamlit widget keys throughout (no DuplicateWidgetID errors)
  - show_n slider safe minimum (no crash when raw_log_count = 0)
  - EVTX upload writes to /tmp (writable on Streamlit Cloud)
  - All tabs fully complete — nothing truncated
  - Session summary panel added to Response Centre
"""

import streamlit as st
import sys
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import time
from datetime import datetime, timezone

# ── CRITICAL: set sys.path BEFORE any src imports ─────────────────────────────
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_APP_DIR, "..", "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# ── Imports — wrapped so startup error is readable, not a raw traceback ───────
try:
    from soc_pipeline    import run_from_logs, run_from_evtx, PipelineResult
    from predict         import check_ip_reputation
    from log_parser      import parse_evtx
    from timeline_engine import get_progression_summary, get_pivot_events
    from scoring_engine  import ScoringConfig
    _IMPORTS_OK    = True
    _IMPORT_ERROR  = ""
except Exception as _imp_err:
    _IMPORTS_OK   = False
    _IMPORT_ERROR = str(_imp_err)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG  (must be the very first Streamlit call)
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="SOC AI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# CSS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
[data-testid="stSidebar"]    { background-color: #0d1117; }
.block-container              { padding-top: 1.2rem; padding-bottom: 1rem; }
div[data-testid="stMetric"]  { background: #161b22; border: 1px solid #30363d;
                                border-radius: 8px; padding: 10px 14px; }
.stAlert                      { border-radius: 6px; }
div[data-testid="stExpander"] { border: 1px solid #21262d; border-radius: 6px; }
hr                            { border-color: #21262d; }
code                          { background: #161b22 !important; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR  — ALL sidebar widgets must live inside this block
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.title("🛡️ SOC AI Platform")
    st.caption("v3.1 — Hybrid Detection Engine")
    st.divider()

    # ── Live monitoring ───────────────────────────────────────────────────────
    st.subheader("⚙️ Live Monitoring")
    auto_refresh = st.checkbox("🔄 Auto-Refresh", key="sb_autorefresh")
    if auto_refresh:
        refresh_rate = st.slider("Interval (sec)", 10, 120, 30, key="sb_interval")
        time.sleep(refresh_rate)
        st.rerun()

    st.divider()

    # ── Scoring weights ───────────────────────────────────────────────────────
    st.subheader("🔧 Scoring Weights")
    use_custom = st.checkbox("Customise weights", key="sb_custom")

    if use_custom and _IMPORTS_OK:
        w_ml    = st.slider("ML Classifier",    0.0, 1.0, 0.25, 0.05, key="sb_wml")
        w_anom  = st.slider("Anomaly (IsoFor)", 0.0, 1.0, 0.20, 0.05, key="sb_wanom")
        w_base  = st.slider("Stat. Baseline",   0.0, 1.0, 0.15, 0.05, key="sb_wbase")
        w_ueba  = st.slider("UEBA",             0.0, 1.0, 0.15, 0.05, key="sb_wueba")
        w_corr  = st.slider("Correlation",      0.0, 1.0, 0.15, 0.05, key="sb_wcorr")
        w_intel = st.slider("Threat Intel",     0.0, 1.0, 0.10, 0.05, key="sb_wintel")
        total   = w_ml + w_anom + w_base + w_ueba + w_corr + w_intel
        if abs(total - 1.0) > 0.01:
            st.warning(f"Weights sum to {total:.2f} — will auto-normalise")
        CUSTOM_CONFIG = ScoringConfig(
            weight_ml=w_ml, weight_anomaly=w_anom, weight_baseline=w_base,
            weight_ueba=w_ueba, weight_correlation=w_corr, weight_threat_intel=w_intel,
        ).renormalize()
    else:
        CUSTOM_CONFIG = ScoringConfig() if _IMPORTS_OK else None

    st.divider()

    # ── OSINT quick links ─────────────────────────────────────────────────────
    st.subheader("🔗 OSINT Links")
    st.markdown("- [MITRE ATT&CK](https://attack.mitre.org)")
    st.markdown("- [AbuseIPDB](https://www.abuseipdb.com)")
    st.markdown("- [VirusTotal](https://www.virustotal.com)")
    st.markdown("- [Shodan](https://www.shodan.io)")
    st.markdown("- [Greynoise](https://greynoise.io)")
    st.divider()
    st.caption("Hybrid ML · IsoFor · UEBA · MITRE ATT&CK")


# ══════════════════════════════════════════════════════════════════════════════
# IMPORT ERROR GATE — show a clear message instead of a raw traceback
# ══════════════════════════════════════════════════════════════════════════════

if not _IMPORTS_OK:
    st.title("🛡️ SOC AI Threat Intelligence Platform")
    st.error(f"**Startup Error — module import failed:**\n\n```\n{_IMPORT_ERROR}\n```")
    st.info("""
**Common causes on Streamlit Cloud:**
1. `model/*.pkl` missing → the app will auto-train on first run — click **Reboot app**
2. `data/sample_logs.csv` missing → ensure it exists in your repo
3. A src/ file has a syntax error → check the Streamlit logs

**Quick fix:** Streamlit dashboard → lower-right corner → **Manage app → Reboot app**
    """)
    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# HEADER + KPI ROW
# ══════════════════════════════════════════════════════════════════════════════

st.title("🛡️ SOC AI Threat Intelligence Platform")
st.caption(
    "Hybrid ML · Isolation Forest · UEBA · "
    "Time-based Correlation · Kill Chain Analysis"
)

st.markdown("---")
k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("🚨 Alerts Today",    "147", "+12")
k2.metric("🔴 Critical",        "9",   "+3")
k3.metric("🟠 High",            "23",  "+5")
k4.metric("🧠 UEBA Anomalies",  "14",  "+2")
k5.metric("⚠️ Suspicious IPs", "31",  "+8")
k6.metric("✅ System",          "Active")
st.markdown("---")


# ══════════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4 = st.tabs([
    "🔧 Manual Simulation",
    "📂 Log Investigation",
    "📊 Threat Intel",
    "📋 Response Centre",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — MANUAL SIMULATION
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Manual Alert Simulation")
    st.caption("Run any event through the full hybrid detection pipeline.")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**Connection Details**")
        failed_logins = st.slider(
            "Failed Login Attempts", 0, 50, 5, key="t1_fails"
        )
        ip = st.text_input("Source IP Address", "8.8.8.8", key="t1_ip")

    with col2:
        st.markdown("**Origin**")
        location = st.selectbox("Country", [
            "India", "US", "UK", "Germany", "Brazil",
            "Russia", "China", "North Korea"
        ], key="t1_loc")
        device = st.selectbox("Operating System", [
            "Windows", "Linux", "MacOS", "Android", "iOS"
        ], key="t1_dev")

    with col3:
        st.markdown("**Attack Context**")
        alert_type = st.selectbox("Alert / Attack Type", [
            "Normal Login", "Brute Force", "Credential Stuffing",
            "Password Spray", "Suspicious Login", "Suspicious Activity",
            "Malware Execution", "Privilege Escalation", "Credential Dumping",
        ], key="t1_atype")
        st.selectbox("Time of Day", [
            "Business Hours (9–17)", "Evening (17–22)",
            "Night (22–6)",          "Early Morning (6–9)"
        ], key="t1_tod")

    if st.button(
        "🚨 Run Full Pipeline Analysis", type="primary",
        use_container_width=True, key="t1_run"
    ):
        log_entry = {
            "alert_type":    alert_type,
            "source_ip":     ip,
            "failed_logins": failed_logins,
            "location":      location,
            "device":        device,
            "event_id":      "SIM",
        }

        with st.spinner("Running hybrid detection pipeline..."):
            pr: PipelineResult = run_from_logs([log_entry], CUSTOM_CONFIG)

        st.markdown("---")

        # Top metrics
        r1, r2, r3, r4, r5 = st.columns(5)
        r1.metric("Final Risk",   f"{pr.final_score}/100")
        r2.metric("Severity",     pr.severity)
        r3.metric("ML Score",
                  f"{pr.detection_results[0].ml_score:.0f}/100"
                  if pr.detection_results else "—")
        r4.metric("Anomaly Score",
                  f"{pr.detection_results[0].anomaly_score:.0f}/100"
                  if pr.detection_results else "—")
        r5.metric("UEBA Score",
                  f"{pr.ueba_results[0].anomaly_score:.0f}/100"
                  if pr.ueba_results else "—")

        st.markdown("---")
        left, right = st.columns(2)

        with left:
            if pr.final_score >= 60:
                st.error(f"**🚨 {pr.investigation.attack_classification}**")
            elif pr.final_score >= 35:
                st.warning(f"**⚠️ {pr.investigation.attack_classification}**")
            else:
                st.success(f"**✅ {pr.investigation.attack_classification}**")

            st.markdown(f"**Attack Summary:** {pr.investigation.attack_summary}")

            ip_status, ip_score = pr.ip_intel.get(ip, ("🟢 Clean", 0))
            st.info(f"🌐 **IP Intel:** {ip_status}")

            if pr.ueba_results:
                u = pr.ueba_results[0]
                summ = u.behavior_summary
                st.warning(
                    f"🧠 **UEBA:** {u.anomaly_label} — "
                    f"{summ[:120]}{'...' if len(summ) > 120 else ''}"
                )
                if u.anomalies_found:
                    with st.expander("UEBA Anomaly Details"):
                        for a in u.anomalies_found:
                            st.markdown(f"  • {a}")

        with right:
            st.markdown("**📊 Score Breakdown**")
            if pr.scoring.layers:
                fig, ax = plt.subplots(figsize=(5, 3))
                names    = [l.name for l in pr.scoring.layers]
                contribs = [l.contribution for l in pr.scoring.layers]
                colors   = ["#58a6ff", "#56d364", "#e3b341",
                            "#d29922", "#f85149", "#bc8cff"]
                ax.barh(names, contribs, color=colors[:len(names)])
                ax.set_xlabel("Weighted Contribution", color="white")
                ax.set_title("Score Layer Contributions", color="white", fontsize=10)
                ax.set_facecolor("#0d1117")
                fig.patch.set_facecolor("#0d1117")
                ax.tick_params(colors="white", labelsize=8)
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                ax.spines["bottom"].set_color("#30363d")
                ax.spines["left"].set_color("#30363d")
                st.pyplot(fig)
                plt.close()
            st.caption(pr.scoring.breakdown)

        # Analyst reasoning
        st.markdown("---")
        st.markdown("### 🧠 Analyst Reasoning")
        for i, step in enumerate(pr.investigation.reasoning_steps, 1):
            st.markdown(f"**{i}.** {step}")

        # MITRE
        if pr.mitre_techniques:
            st.markdown("**🎯 MITRE ATT&CK Techniques:**")
            cols = st.columns(min(len(pr.mitre_techniques), 3))
            for i, m in enumerate(pr.mitre_techniques):
                cols[i % 3].code(m, language=None)

        # Response actions
        st.markdown("---")
        st.markdown("### 🛡️ Recommended Actions")
        for action in pr.investigation.recommended_actions:
            st.markdown(f"- {action}")

        # IOCs
        if pr.investigation.iocs:
            st.markdown("---")
            st.markdown("### 🔍 Indicators of Compromise")
            ioc_cols = st.columns(3)
            for i, ioc in enumerate(pr.investigation.iocs):
                ioc_type  = ioc.type  if hasattr(ioc, "type")  else ioc.get("type",  "?")
                ioc_value = ioc.value if hasattr(ioc, "value") else ioc.get("value", "?")
                ioc_note  = ioc.note  if hasattr(ioc, "note")  else ioc.get("note",  "")
                icon = ("🔴" if ioc_type == "ip" else
                        "🎯" if ioc_type == "technique" else "🟡")
                ioc_cols[i % 3].markdown(
                    f"{icon} **[{ioc_type.upper()}]** `{ioc_value}`\n\n_{ioc_note}_"
                )


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — LOG INVESTIGATION
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("EVTX Log Investigation")
    st.caption(
        "Upload Windows Event Log files for full SOC investigation. "
        "Sysmon logs, Security logs, and System logs all supported."
    )

    uploaded_file = st.file_uploader(
        "Upload EVTX File", type=["evtx"],
        help="Max 200MB. Export via Event Viewer or: wevtutil epl Security C:\\out.evtx",
        key="t2_upload"
    )

    if not uploaded_file:
        st.info("📂 Upload an EVTX file to begin investigation.")
        st.markdown("""
**Export logs on Windows:**
```powershell
# Security log
wevtutil epl Security C:\\Users\\YourName\\security.evtx

# Sysmon log
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\Users\\YourName\\sysmon.evtx
```
**Supported event IDs:** 4624, 4625, 4648, 4672, 4688, 4698, 4732, 1, 3, 7, 10, 11

**No EVTX?** If the library cannot parse the file, the system automatically falls back
to a realistic simulated attack scenario so the dashboard is always demonstrable.
        """)

    else:
        # Write to /tmp — guaranteed writable on Streamlit Cloud
        tmp_path = "/tmp/_soc_upload.evtx"
        with open(tmp_path, "wb") as f:
            f.write(uploaded_file.read())

        with st.spinner("🔍 Running full SOC pipeline..."):
            pr: PipelineResult = run_from_evtx(tmp_path, CUSTOM_CONFIG)

        # Header stats
        h1, h2, h3, h4, h5 = st.columns(5)
        h1.metric("Events Parsed", pr.raw_log_count)
        h2.metric("Final Risk",     f"{pr.final_score}/100")
        h3.metric("Severity",       pr.severity)
        h4.metric("Unique IPs",     len(pr.unique_ips))
        h5.metric("Pipeline Time",  f"{pr.pipeline_duration_ms}ms")

        threat_label = "🔴 THREAT DETECTED" if pr.is_threat else "🟢 NO SIGNIFICANT THREAT"
        if pr.is_threat:
            st.error(f"**{threat_label}** — {pr.investigation.attack_classification}")
        else:
            st.success(f"**{threat_label}**")

        st.markdown("---")

        # ── Investigation Report ──────────────────────────────────────────────
        st.markdown("## 📋 Investigation Report")
        inv = pr.investigation

        with st.expander("📄 Full Investigation Report", expanded=True):
            st.markdown(f"**Case ID:** `{inv.case_id}`")
            st.markdown(f"**Classification:** {inv.attack_classification}")
            st.markdown(f"**Confidence:** {inv.confidence}%")
            st.markdown(f"**Summary:** {inv.attack_summary}")
            st.divider()
            st.markdown("**Timeline Narrative:**")
            st.markdown(f"> {inv.timeline_narrative}")
            st.divider()
            st.markdown("**Analyst Reasoning:**")
            for i, step in enumerate(inv.reasoning_steps, 1):
                st.markdown(f"{i}. {step}")

        st.markdown("---")

        # ── Three-column: Correlation + Kill Chain + UEBA ─────────────────────
        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown("### 🧠 Correlation")
            corr = pr.correlation
            st.caption(
                f"{corr.total_events} events · "
                f"{corr.unique_ips} IPs · "
                f"Confidence: {corr.attack_confidence}%"
            )
            for alert in corr.alerts:
                sev = alert.severity
                fn  = (st.error   if sev == "Critical" else
                       st.warning if sev in ("High", "Medium") else
                       st.info)
                desc = alert.description
                fn(
                    f"**{alert.name}** *({sev})*\n\n"
                    f"{desc[:120]}{'...' if len(desc) > 120 else ''}"
                )
            if corr.windows_analyzed:
                w = corr.windows_analyzed
                st.caption(
                    f"Burst: {w.get('burst', 0)} · "
                    f"Slow: {w.get('slow', 0)} · "
                    f"Chain: {w.get('chain', 0)}"
                )

        with c2:
            st.markdown("### 🧬 Kill Chain")
            tl_meta = pr.timeline.meta
            if tl_meta.attack_progression:
                st.progress(
                    min(tl_meta.completeness_pct / 100, 1.0),
                    text=f"Coverage: {tl_meta.completeness_pct}% of 6-stage chain"
                )
                for stage in tl_meta.attack_progression:
                    icon = "🔴" if stage in (
                        "Privilege Escalation", "Credential Access",
                        "Lateral Movement", "Exfiltration"
                    ) else "🟠"
                    st.markdown(f"{icon} **{stage}**")
            else:
                st.info("No kill chain stages detected.")
            if tl_meta.pivot_count > 0:
                st.warning(f"⚡ {tl_meta.pivot_count} escalation pivot(s) detected")

        with c3:
            st.markdown("### 🧠 UEBA Insights")
            if pr.ueba_results:
                for u in sorted(
                    pr.ueba_results, key=lambda x: x.anomaly_score, reverse=True
                )[:3]:
                    score = u.anomaly_score
                    icon  = "🔴" if score >= 70 else "🟡" if score >= 40 else "🟢"
                    st.markdown(f"{icon} **{u.ip}** — Score: {score:.0f}/100")
                    if u.spike_detected:
                        st.caption("⚡ Activity spike detected")
                    if u.new_location:
                        st.caption("🌍 New location observed")
                    if u.off_hours_access:
                        st.caption("🌙 Off-hours access")
                    if u.anomalies_found:
                        first = u.anomalies_found[0]
                        st.caption(
                            f"📋 {first[:80]}{'...' if len(first) > 80 else ''}"
                        )
            else:
                st.info("No UEBA data available.")

        st.markdown("---")

        # ── Attack Timeline ───────────────────────────────────────────────────
        st.markdown("### 📈 Attack Progression Timeline")

        if pr.timeline.entries:
            tl = pr.timeline
            st.info(f"**{get_progression_summary(tl)}**")

            severity_num = {
                "Normal Login": 1, "Suspicious Login": 2,
                "Suspicious Activity": 3, "Password Spray": 4,
                "Credential Stuffing": 5, "Brute Force": 6,
                "Malware Execution": 7, "Privilege Escalation": 8,
                "Credential Dumping": 9,
            }
            color_map = {
                1: "#2ea043", 2: "#56d364", 3: "#e3b341", 4: "#d29922",
                5: "#f0883e", 6: "#f85149", 7: "#da3633", 8: "#b91c1c",
                9: "#7f1d1d",
            }

            y      = [severity_num.get(e.alert_type, 1) for e in tl.entries]
            x      = list(range(len(y)))
            colors = [color_map.get(v, "#2ea043") for v in y]

            fig, ax = plt.subplots(figsize=(12, 4))
            ax.plot(x, y, color="#58a6ff", linewidth=1.2, alpha=0.35)
            ax.scatter(x, y, c=colors, s=70, zorder=5)

            for p in get_pivot_events(tl):
                pi = p.index
                if pi < len(y):
                    ax.annotate(
                        "⬆ PIVOT",
                        xy=(pi, y[pi]), xytext=(pi, y[pi] + 0.6),
                        fontsize=7, color="#f85149", ha="center",
                        arrowprops=dict(arrowstyle="-", color="#f85149", lw=0.8),
                    )

            ax.set_yticks([1, 2, 3, 4, 5, 6, 7, 8, 9])
            ax.set_yticklabels([
                "Normal", "Susp.Login", "Susp.Act", "Pwd Spray",
                "Cred.Stuff", "Brute Force", "Malware", "PrivEsc", "Cred.Dump"
            ], fontsize=7)
            ax.set_xlabel("Event Sequence", color="white")
            ax.set_ylabel("Threat Level",   color="white")
            ax.set_title("Attack Progression (pivots annotated)", color="white")
            ax.set_facecolor("#0d1117")
            fig.patch.set_facecolor("#0d1117")
            ax.tick_params(colors="white")
            ax.spines["bottom"].set_color("#30363d")
            ax.spines["left"].set_color("#30363d")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.legend(
                handles=[
                    mpatches.Patch(color="#2ea043", label="Normal"),
                    mpatches.Patch(color="#e3b341", label="Suspicious"),
                    mpatches.Patch(color="#f0883e", label="High Risk"),
                    mpatches.Patch(color="#da3633", label="Malware/PrivEsc"),
                    mpatches.Patch(color="#7f1d1d", label="Critical"),
                ],
                loc="upper left", facecolor="#161b22",
                edgecolor="#30363d", labelcolor="white", fontsize=8
            )
            st.pyplot(fig)
            plt.close()
        else:
            st.info("No timeline entries to display.")

        st.markdown("---")

        # ── Event Table ───────────────────────────────────────────────────────
        st.markdown("### 📊 Event Analysis")

        n_events = max(pr.raw_log_count, 1)

        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            threats_only = st.checkbox("Threat events only", key="t2_thronly")
        with fc2:
            min_risk = st.slider("Min risk score", 0, 100, 0, key="t2_minrisk")
        with fc3:
            show_max = max(5, min(50, n_events))
            show_def = min(10, show_max)
            show_n   = (
                st.slider("Show N events", 5, show_max, show_def, key="t2_shown")
                if show_max > 5 else 5
            )

        for entry in pr.timeline.entries[:show_n]:
            det = None
            if len(pr.detection_results) > entry.index:
                det = pr.detection_results[entry.index]

            det_score = det.final_risk_score if det else 0
            is_threat = det_score >= 35 if det else False

            if threats_only and not is_threat:
                continue
            if det_score < min_risk:
                continue

            icon   = "🚨" if is_threat else "✅"
            pivot  = " ⬆ PIVOT" if entry.is_pivot else ""
            header = (
                f"{icon} {entry.timestamp_rel} | {entry.alert_type} | "
                f"{entry.stage} | Risk: {det_score}/100{pivot}"
            )

            with st.expander(header, expanded=(is_threat and entry.index < 3)):
                a1, a2, a3, a4 = st.columns(4)
                a1.markdown(f"**Event ID:** `{entry.event_id}`")
                a2.markdown(f"**Source IP:** `{entry.source_ip}`")
                a3.markdown(f"**MITRE:** `{entry.technique_id}`")
                a4.markdown(f"**Dwell:** {entry.dwell_label}")

                b1, b2 = st.columns(2)
                b1.markdown(f"**Stage:** {entry.stage}")
                b2.markdown(f"**Technique:** {entry.technique_name}")

                if det:
                    st.caption(
                        f"ML: {det.ml_score:.0f}/100 | "
                        f"Anomaly: {det.anomaly_score:.0f}/100 | "
                        f"Baseline: {det.baseline_score:.0f}/100 | "
                        f"{det.anomaly_label}"
                    )
                    for r in det.baseline_reasons:
                        st.markdown(f"  — {r}")

                if is_threat:
                    if det_score >= 80:
                        st.error("🔴 Block IP · Isolate endpoint · Escalate immediately")
                    elif det_score >= 60:
                        st.warning("🟠 Watchlist · Review auth logs · Alert team")
                    else:
                        st.info("🟡 Monitor · Check baseline · Log for audit")

        # ── IOC Panel ─────────────────────────────────────────────────────────
        if inv.iocs:
            st.markdown("---")
            st.markdown("### 🔍 Indicators of Compromise")
            ioc_cols = st.columns(3)
            for i, ioc in enumerate(inv.iocs):
                ioc_type  = ioc.type  if hasattr(ioc, "type")  else ioc.get("type",  "?")
                ioc_value = ioc.value if hasattr(ioc, "value") else ioc.get("value", "?")
                ioc_note  = ioc.note  if hasattr(ioc, "note")  else ioc.get("note",  "")
                icon = ("🔴" if ioc_type == "ip" else
                        "🎯" if ioc_type == "technique" else "🟡")
                ioc_cols[i % 3].markdown(
                    f"{icon} **[{ioc_type.upper()}]** `{ioc_value}`\n\n_{ioc_note}_"
                )


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — THREAT INTEL
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("IP Threat Intelligence")
    st.caption("Real-time AbuseIPDB lookup + local threat list.")

    lc, rc = st.columns([2, 1])
    with lc:
        lookup_ip = st.text_input(
            "IP to investigate", placeholder="185.220.101.1", key="t3_ip"
        )
    with rc:
        st.markdown("<br>", unsafe_allow_html=True)
        do_lookup = st.button(
            "🔍 Investigate", type="primary",
            use_container_width=True, key="t3_btn"
        )

    st.caption("Quick-test IPs:")
    q1, q2, q3, q4 = st.columns(4)
    if q1.button("185.220.101.1 *(Tor)*",   use_container_width=True, key="t3_q1"):
        lookup_ip, do_lookup = "185.220.101.1", True
    if q2.button("45.33.32.1 *(Known bad)*", use_container_width=True, key="t3_q2"):
        lookup_ip, do_lookup = "45.33.32.1", True
    if q3.button("8.8.8.8 *(Google DNS)*",   use_container_width=True, key="t3_q3"):
        lookup_ip, do_lookup = "8.8.8.8", True
    if q4.button("1.1.1.1 *(Cloudflare)*",   use_container_width=True, key="t3_q4"):
        lookup_ip, do_lookup = "1.1.1.1", True

    if do_lookup and lookup_ip:
        with st.spinner(f"Querying threat intel for {lookup_ip} ..."):
            ip_status_str, ip_score = check_ip_reputation(lookup_ip)

        st.markdown("---")
        m1, m2, m3 = st.columns(3)
        m1.metric("IP Address",  lookup_ip)
        m2.metric("Abuse Score", f"{ip_score}/100")
        m3.metric("Verdict",
                  "🔴 Malicious"  if ip_score >= 75 else
                  "🟡 Suspicious" if ip_score >= 30 else "🟢 Clean")

        st.markdown(f"**Full status:** {ip_status_str}")

        if ip_score >= 75:
            st.error(f"**🔴 MALICIOUS IP** — Score {ip_score}/100. Block immediately.")
        elif ip_score >= 30:
            st.warning(f"**🟡 SUSPICIOUS IP** — Score {ip_score}/100. Monitor closely.")
        else:
            st.success(f"**🟢 CLEAN IP** — Score {ip_score}/100.")

        st.markdown("**Recommended Actions:**")
        if ip_score >= 75:
            st.markdown("""
1. 🔴 Block IP at firewall immediately
2. Search logs for all connections from this IP
3. Check if any accounts authenticated from this IP
4. Revoke active sessions
5. Add to permanent blocklist + file incident
            """)
        elif ip_score >= 30:
            st.markdown("""
1. 🟡 Add to watchlist
2. Enable rate limiting
3. Review recent auth attempts
4. Temporary block if activity escalates
            """)
        else:
            st.markdown("1. 🟢 No action required — continue standard monitoring")

        st.markdown("---")
        st.markdown("**🌐 Investigate further:**")
        o1, o2, o3, o4, o5 = st.columns(5)
        o1.markdown(f"[AbuseIPDB](https://www.abuseipdb.com/check/{lookup_ip})")
        o2.markdown(f"[VirusTotal](https://www.virustotal.com/gui/ip-address/{lookup_ip})")
        o3.markdown(f"[Shodan](https://www.shodan.io/host/{lookup_ip})")
        o4.markdown(f"[IPInfo](https://ipinfo.io/{lookup_ip})")
        o5.markdown(f"[Greynoise](https://viz.greynoise.io/ip/{lookup_ip})")

    else:
        st.markdown("---")
        st.markdown("### OSINT Reference Table")
        st.table({
            "Tool":    ["AbuseIPDB",       "VirusTotal",      "Shodan",
                        "Greynoise",        "IPInfo"],
            "Purpose": ["IP abuse reports", "Multi-engine scan","Device intel",
                        "Noise vs targeted","Geolocation/ASN"],
            "URL":     ["abuseipdb.com",   "virustotal.com",  "shodan.io",
                        "greynoise.io",    "ipinfo.io"],
        })


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — RESPONSE CENTRE
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🛡️ Response Centre")
    st.caption("Log analyst decisions and track response actions.")

    if "response_log" not in st.session_state:
        st.session_state.response_log = []

    st.markdown("### Take Action on an Alert")

    ra1, ra2 = st.columns(2)
    with ra1:
        action_ip   = st.text_input("Target IP", placeholder="45.33.32.1", key="t4_ip")
        action_type = st.selectbox("Action", [
            "🔴 Block IP at Firewall",
            "🟡 Add to Watchlist",
            "🔍 Escalate to Tier 2",
            "✅ Mark as False Positive",
            "📋 Open Incident Ticket",
            "🔒 Force Password Reset",
            "📁 Preserve Evidence",
            "🔕 Suppress for 24h",
        ], key="t4_atype")
    with ra2:
        analyst_name = st.text_input(
            "Analyst Name", placeholder="Aman Ali", key="t4_analyst"
        )
        action_notes = st.text_area(
            "Notes", placeholder="Reason for action...", height=100, key="t4_notes"
        )

    if st.button("✅ Log Action", type="primary", key="t4_logbtn"):
        if action_ip and analyst_name:
            entry = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "analyst":   analyst_name,
                "ip":        action_ip,
                "action":    action_type,
                "notes":     action_notes,
            }
            st.session_state.response_log.append(entry)
            st.success(f"✅ Action logged: {action_type} for {action_ip}")
        else:
            st.warning("Please fill in both IP and Analyst Name.")

    st.markdown("---")
    st.markdown("### Action Log")

    if st.session_state.response_log:
        for entry in reversed(st.session_state.response_log):
            sev_icon = ("🔴" if "Block"    in entry["action"] else
                        "🔍" if "Escalate" in entry["action"] else
                        "✅" if "False"    in entry["action"] else "📋")
            with st.expander(
                f"{sev_icon} {entry['timestamp']} — {entry['action']} — IP: {entry['ip']}",
                expanded=False
            ):
                st.markdown(f"**Analyst:** {entry['analyst']}")
                st.markdown(f"**Action:**  {entry['action']}")
                st.markdown(f"**Target:**  `{entry['ip']}`")
                if entry["notes"]:
                    st.markdown(f"**Notes:**   {entry['notes']}")

        if st.button("🗑️ Clear Action Log", key="t4_clear"):
            st.session_state.response_log = []
            st.rerun()
    else:
        st.info("No actions logged yet. Use the form above to log analyst decisions.")

    st.markdown("---")
    st.markdown("### 📋 Quick Response Playbooks")

    pb1, pb2, pb3 = st.columns(3)

    with pb1:
        with st.expander("🔴 Brute Force Playbook"):
            st.markdown("""
1. Identify source IP(s) from SIEM
2. Check AbuseIPDB score
3. Block IP at firewall / WAF
4. Review auth logs for past 24 hours
5. Reset credentials for targeted accounts
6. Enable MFA if not already active
7. File P2 incident ticket
            """)

    with pb2:
        with st.expander("🔴 Credential Dumping Playbook"):
            st.markdown("""
1. Isolate affected endpoint immediately
2. Assume ALL credentials are compromised
3. Rotate ALL passwords + service accounts
4. Revoke certificates / tokens / API keys
5. Check for lateral movement indicators
6. File P1 incident + notify management
7. Engage Incident Response team
            """)

    with pb3:
        with st.expander("🟡 Suspicious Login Playbook"):
            st.markdown("""
1. Contact account owner directly
2. Verify if travel / VPN is expected
3. Check for impossible travel (time + distance)
4. Review recent account activity
5. Add IP to 30-day watchlist
6. Enable step-up authentication
7. Log for audit trail
            """)

    # Session summary
    st.markdown("---")
    st.markdown("### 📊 Session Summary")
    total_logged = len(st.session_state.response_log)
    if total_logged > 0:
        action_counts: dict = {}
        for e in st.session_state.response_log:
            a = e["action"]
            action_counts[a] = action_counts.get(a, 0) + 1
        s1, s2 = st.columns(2)
        s1.metric("Total Actions Logged", total_logged)
        s2.metric("Unique Action Types",  len(action_counts))
        st.markdown("**Action breakdown this session:**")
        for action, count in sorted(action_counts.items(), key=lambda x: -x[1]):
            st.markdown(f"  - {action}: **{count}**")
    else:
        st.caption("No actions logged this session.")
