"""
app/streamlit_app.py
════════════════════
SOC AI Platform — real-time triage console.

Tabs:
  🔴 Live Monitor       — simulator or watch-folder feed → pipeline → queue
  🔧 Scenario Simulator — "what would the pipeline do with this event?"
  📂 Log Investigation  — EVTX upload → full pipeline
  📊 Threat Intel       — AbuseIPDB lookup
  📋 Triage Queue       — persistent alert queue + analyst workflow

Honesty rules enforced in this UI:
  - No hardcoded KPI numbers; header metrics come from the triage DB.
  - The simulator is labeled SIMULATED everywhere it appears.
  - The scenario tab asks for RAW event parameters (event ID, hour, …);
    the pipeline derives the category — the user never hands it the label.
  - Empty parse results show an honest empty state, never fake events.
"""

import streamlit as st
import sys
import os
import time
import matplotlib.pyplot as plt
from datetime import datetime, timezone

# ── CRITICAL: set sys.path BEFORE any src imports ─────────────────────────────
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_APP_DIR, "..", "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# ── Imports — wrapped so startup errors are readable ──────────────────────────
try:
    from soc_pipeline    import run_from_logs, run_from_evtx, PipelineResult
    from scoring_engine  import ScoringConfig
    from predict         import check_ip_reputation
    from log_parser      import parse_evtx, EVENT_ID_MAP
    from timeline_engine import get_progression_summary, get_pivot_events
    from triage_store    import TriageStore
    from simulator       import AttackSimulator, SCENARIOS
    from ingest          import WatchFolder
    import feedback_model
    import mitre
    _IMPORTS_OK   = True
    _IMPORT_ERROR = ""
except Exception as _imp_err:  # noqa: BLE001
    _IMPORTS_OK   = False
    _IMPORT_ERROR = str(_imp_err)


st.set_page_config(
    page_title="SOC AI Triage Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _json_loads(s):
    import json as _json
    try:
        return _json.loads(s)
    except Exception:
        return []

st.markdown("""
<style>
[data-testid="stSidebar"]    { background-color: #0d1117; }
.block-container              { padding-top: 1.2rem; padding-bottom: 1rem; }
div[data-testid="stMetric"]  { background: #161b22; border: 1px solid #30363d;
                                border-radius: 8px; padding: 10px 14px; }
div[data-testid="stExpander"] { border: 1px solid #21262d; border-radius: 6px; }
hr                            { border-color: #21262d; }
code                          { background: #161b22 !important; }
</style>
""", unsafe_allow_html=True)


if not _IMPORTS_OK:
    st.title("🛡️ SOC AI Triage Console")
    st.error(f"**Startup Error — module import failed:**\n\n```\n{_IMPORT_ERROR}\n```")
    st.info("Check Streamlit logs; most likely a missing dependency. "
            "`pip install -r requirements.txt` then **Manage app → Reboot app**.")
    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.title("🛡️ SOC AI Triage")
    st.caption("rules · Isolation Forest · UEBA · correlation")
    st.divider()

    st.subheader("⚙️ Live Monitoring")
    auto_refresh = st.checkbox("🔄 Auto-refresh", key="sb_autorefresh",
                               help="Refresh the page on an interval (applies after render).")
    refresh_rate = st.slider("Interval (sec)", 10, 120, 30, key="sb_interval")

    st.divider()
    st.subheader("🔧 Scoring Weights")
    use_custom = st.checkbox("Customise weights", key="sb_custom")
    if use_custom:
        w_rules = st.slider("Rules Engine",     0.0, 1.0, 0.25, 0.05, key="sb_wrules")
        w_anom  = st.slider("Anomaly (IsoFor)", 0.0, 1.0, 0.20, 0.05, key="sb_wanom")
        w_base  = st.slider("Stat. Baseline",   0.0, 1.0, 0.15, 0.05, key="sb_wbase")
        w_ueba  = st.slider("UEBA",             0.0, 1.0, 0.15, 0.05, key="sb_wueba")
        w_corr  = st.slider("Correlation",      0.0, 1.0, 0.15, 0.05, key="sb_wcorr")
        w_intel = st.slider("Threat Intel",     0.0, 1.0, 0.10, 0.05, key="sb_wintel")
        total = w_rules + w_anom + w_base + w_ueba + w_corr + w_intel
        if abs(total - 1.0) > 0.01:
            st.warning(f"Weights sum to {total:.2f} — will auto-normalise")
        CUSTOM_CONFIG = ScoringConfig(
            weight_rules=w_rules, weight_anomaly=w_anom,
            weight_baseline=w_base, weight_ueba=w_ueba,
            weight_correlation=w_corr, weight_threat_intel=w_intel,
        ).renormalize()
    else:
        CUSTOM_CONFIG = ScoringConfig()

    st.divider()
    st.subheader("🔗 OSINT Links")
    st.markdown("- [MITRE ATT&CK](https://attack.mitre.org)")
    st.markdown("- [AbuseIPDB](https://www.abuseipdb.com)")
    st.markdown("- [VirusTotal](https://www.virustotal.com)")
    st.markdown("- [Greynoise](https://greynoise.io)")
    st.divider()
    st.caption("Analyst-feedback model: " +
               ("🟢 trained" if feedback_model.available() else "⚪ cold start"))


# ══════════════════════════════════════════════════════════════════════════════
# HEADER — KPIs from the REAL triage DB (never hardcoded)
# ══════════════════════════════════════════════════════════════════════════════

st.title("🛡️ SOC AI Triage Console")
st.caption("Real-time alert triage · honest ML · persistent analyst workflow")

store = TriageStore()
stats = store.stats()
by_status = stats["by_status"]

st.markdown("---")
k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("📥 Alerts in Queue", stats["total"])
k2.metric("🔴 Open Critical", stats["open_critical"])
k3.metric("🔍 Investigating", by_status.get("investigating", 0))
k4.metric("✅ Confirmed Threats", by_status.get("closed_true_positive", 0))
k5.metric("❌ False Positives", by_status.get("closed_false_positive", 0))
fb = feedback_model.model_info()
k6.metric("🧠 Feedback Model",
          "Trained" if fb.get("available") else "Cold start")
st.markdown("---")


tab_live, tab_sim, tab_evtx, tab_intel, tab_queue = st.tabs([
    "🔴 Live Monitor",
    "🔧 Scenario Simulator",
    "📂 Log Investigation",
    "📊 Threat Intel",
    "📋 Triage Queue",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE MONITOR
# ════════════════════════════════════════════════════════════════════════════
with tab_live:
    st.subheader("Live Event Feed")
    st.caption("Stream events through the full detection pipeline as they arrive.")

    if "feed" not in st.session_state:
        st.session_state.feed = None
    if "feed_stats" not in st.session_state:
        st.session_state.feed_stats = {"events": 0, "alerts": 0}

    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        feed_kind = st.selectbox("Feed source", ["Demo simulator", "Watch folder"],
                                 key="live_kind")
    with c2:
        if feed_kind == "Demo simulator":
            scenario = st.selectbox("Scenario", list(SCENARIOS.keys()),
                                    key="live_scenario")
            st.caption("⚠️ SIMULATED FEED — synthetic demo traffic, not real logs.")
        else:
            watch_path = st.text_input("Folder to watch", "watch/",
                                       key="live_watch")
            st.caption("Drop .evtx / .csv files in the folder; new data is picked up.")
    with c3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.session_state.feed is None:
            start = st.button("▶ Start feed", type="primary",
                              use_container_width=True, key="live_start")
            if start:
                if feed_kind == "Demo simulator":
                    st.session_state.feed = ("sim", AttackSimulator(scenario))
                else:
                    st.session_state.feed = ("watch", WatchFolder(
                        st.session_state.get("live_watch", "watch/")))
                st.rerun()
        else:
            if st.button("⏹ Stop feed", use_container_width=True,
                         key="live_stop"):
                st.session_state.feed = None
                st.rerun()

    if st.session_state.feed is not None:
        kind, feed_obj = st.session_state.feed
        try:
            new_events = feed_obj.poll()
        except Exception as e:  # noqa: BLE001
            st.error(f"Feed error: {e}")
            new_events = []

        if new_events:
            with st.spinner(f"Scoring {len(new_events)} new event(s)…"):
                pr: PipelineResult = run_from_logs(new_events, CUSTOM_CONFIG)
            st.session_state.feed_stats["events"] += len(new_events)
            st.session_state.feed_stats["alerts"] += len(pr.triage_alert_ids)
            if pr.triage_alert_ids:
                st.warning(f"🚨 {len(pr.triage_alert_ids)} alert(s) added to the "
                           f"triage queue — see the Triage Queue tab.")
            if kind == "sim" and feed_obj.finished:
                st.info("Scenario finished. Restart the feed to replay it.")

        fs = st.session_state.feed_stats
        m1, m2 = st.columns(2)
        m1.metric("Events processed (this session)", fs["events"])
        m2.metric("Alerts queued (this session)", fs["alerts"])

        # Latest queue state
        recent = store.list_alerts(limit=10)
        if recent:
            st.markdown("### Latest alerts")
            for a in recent:
                icon = {"Critical": "🔴", "High": "🟠",
                        "Medium": "🟡"}.get(a["severity"], "🟢")
                st.markdown(
                    f"{icon} **#{a['id']}** {a['alert_type'][:60]} — "
                    f"risk {a['risk_score']} · {a['source_ip']} · "
                    f"`{a['status']}` · ×{a['event_count']}")
    else:
        st.info("Start a feed to begin live triage. The demo simulator plays a "
                "scripted attack; the watch folder ingests your own log files.")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — SCENARIO SIMULATOR (honest: raw event in, pipeline scores it)
# ════════════════════════════════════════════════════════════════════════════
with tab_sim:
    st.subheader("Scenario Simulator")
    st.caption("Describe a RAW event — the pipeline derives the category and "
               "scores it. You never hand it the answer.")

    EVENT_CHOICES = {
        "4625 — Failed logon": "4625",
        "4624 — Successful logon": "4624",
        "4648 — Explicit-credential logon": "4648",
        "4672 — Special privileges assigned": "4672",
        "4688 — Process created": "4688",
        "4698 — Scheduled task created": "4698",
        "4732 — Added to privileged group": "4732",
        "Sysmon 1 — Process created": "1",
        "Sysmon 3 — Network connection": "3",
        "Sysmon 10 — Process access": "10",
    }

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**Event**")
        eid_label = st.selectbox("Windows/Sysmon Event ID", list(EVENT_CHOICES),
                                 key="sim_eid")
        event_id = EVENT_CHOICES[eid_label]
        failed_logins = st.slider("Failed login count", 0, 50, 5, key="sim_fails")
        proc_risk = st.checkbox("Malicious process / suspicious command line",
                                key="sim_proc")
    with col2:
        st.markdown("**Origin**")
        ip = st.text_input("Source IP", "45.33.32.1", key="sim_ip")
        hour = st.slider("Hour of day (UTC)", 0, 23, 3, key="sim_hour")
        location = st.selectbox("Country", ["Unknown", "India", "US", "UK",
                                            "Germany", "Russia", "China",
                                            "North Korea", "Brazil"],
                                key="sim_loc")
    with col3:
        st.markdown("**Context**")
        device = st.selectbox("OS", ["Unknown", "Windows", "Linux", "MacOS"],
                              key="sim_dev")
        st.markdown("")
        st.caption(f"Parser category for {event_id}: "
                   f"**{EVENT_ID_MAP.get(event_id, '?')}**")

    if st.button("🔍 Score this event", type="primary",
                 use_container_width=True, key="sim_run"):
        ts = datetime.now(timezone.utc).replace(hour=hour, minute=0,
                                                second=0, microsecond=0)
        log_entry = {
            "event_id":      event_id,
            "timestamp":     ts.isoformat(),
            "alert_type":    EVENT_ID_MAP.get(event_id, "Suspicious Activity"),
            "failed_logins": failed_logins,
            "source_ip":     ip or None,
            "location":      location,
            "device":        device,
            "process_risk":  1 if proc_risk else 0,
        }
        with st.spinner("Running detection pipeline…"):
            pr: PipelineResult = run_from_logs([log_entry], CUSTOM_CONFIG,
                                               ingest=False)
        det = pr.detection_results[0]

        st.markdown("---")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Final Risk", f"{det.final_risk_score}/100")
        r2.metric("Severity", det.severity)
        r3.metric("Rules", f"{det.rules_score:.0f}/100")
        r4.metric("Anomaly (ML)", f"{det.anomaly_score:.0f}/100 — {det.anomaly_label}")

        st.markdown("### Why this score")
        for rsn in det.rules_reasons:
            st.markdown(f"• {rsn}")
        for rsn in det.baseline_reasons:
            st.markdown(f"• {rsn}")
        if det.anomaly_score >= 60:
            st.markdown("• Unsupervised anomaly model: stranger than ~95% of "
                        "benign baseline activity.")
        st.caption("Anomaly model: Isolation Forest trained on benign baselines "
                   "only — no labels. Rules: transparent heuristics on "
                   "observable signals.")

        if pr.mitre_techniques:
            st.markdown("**🎯 MITRE ATT&CK:**")
            cols = st.columns(min(len(pr.mitre_techniques), 3))
            for i, m_ in enumerate(pr.mitre_techniques):
                cols[i % 3].code(m_, language=None)


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — LOG INVESTIGATION (EVTX upload)
# ════════════════════════════════════════════════════════════════════════════
with tab_evtx:
    st.subheader("EVTX Log Investigation")
    st.caption("Upload a Windows Event Log (.evtx) for full pipeline analysis. "
               "Sysmon, Security, and System logs supported.")

    uploaded_file = st.file_uploader("Upload EVTX File", type=["evtx"],
                                     key="t2_upload")

    if not uploaded_file:
        st.info("📂 Upload an EVTX file to begin investigation.")
        st.markdown("""
**Export logs on Windows:**
```powershell
wevtutil epl Security C:\\Users\\YourName\\security.evtx
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\Users\\YourName\\sysmon.evtx
```
**Mapped event IDs:** 4624, 4625, 4648, 4672, 4688, 4698, 4732,
Sysmon 1, 3, 7, 10, 11.
        """)
    else:
        tmp_path = "/tmp/_soc_upload.evtx"
        with open(tmp_path, "wb") as f:
            f.write(uploaded_file.read())

        try:
            with st.spinner("🔍 Running full SOC pipeline…"):
                pr: PipelineResult = run_from_evtx(tmp_path, CUSTOM_CONFIG)
        except RuntimeError as e:
            st.error(f"Could not parse the file: {e}")
            st.stop()

        if pr.raw_log_count == 0:
            st.warning("⚠️ **0 events parsed.** The file may be empty, corrupt, "
                       "or contain no supported event IDs. No fake data was "
                       "substituted — try a different file.")
            st.stop()

        h1, h2, h3, h4, h5 = st.columns(5)
        h1.metric("Events Parsed", pr.raw_log_count)
        h2.metric("Final Risk", f"{pr.final_score}/100")
        h3.metric("Severity", pr.severity)
        h4.metric("Unique IPs", len(pr.unique_ips))
        h5.metric("Pipeline Time", f"{pr.pipeline_duration_ms}ms")

        if pr.triage_alert_ids:
            st.info(f"📥 {len(pr.triage_alert_ids)} alert(s) added to the triage queue.")

        threat_label = ("🔴 THREAT DETECTED" if pr.is_threat
                        else "🟢 NO SIGNIFICANT THREAT")
        if pr.is_threat:
            st.error(f"**{threat_label}** — {pr.investigation.attack_classification}")
        else:
            st.success(f"**{threat_label}**")
        st.markdown("---")

        # Investigation report
        st.markdown("## 📋 Investigation Report")
        inv = pr.investigation
        with st.expander("📄 Full Investigation Report", expanded=True):
            st.markdown(f"**Case ID:** `{inv.case_id}`")
            st.markdown(f"**Classification:** {inv.attack_classification}")
            st.markdown(f"**Confidence:** {inv.confidence}%")
            st.markdown(f"**Summary:** {inv.attack_summary}")
            st.divider()
            st.markdown("**Analyst Reasoning:**")
            for i, step in enumerate(inv.reasoning_steps, 1):
                st.markdown(f"{i}. {step}")

        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("### 🧠 Correlation")
            corr = pr.correlation
            st.caption(f"{corr.total_events} events · {corr.unique_ips} IPs · "
                       f"Confidence: {corr.attack_confidence}%")
            for alert in corr.alerts:
                sev = alert.severity
                fn = (st.error if sev == "Critical" else
                      st.warning if sev in ("High", "Medium") else st.info)
                fn(f"**{alert.name}** *({sev}, conf {alert.confidence}%)*\n\n"
                   f"{alert.description[:140]}")
        with c2:
            st.markdown("### 🧬 Attack Progression")
            tl_meta = pr.timeline.meta
            if tl_meta.attack_progression:
                st.progress(min(tl_meta.completeness_pct / 100, 1.0),
                            text=f"Coverage: {tl_meta.completeness_pct}% of chain")
                for stage in tl_meta.attack_progression:
                    st.markdown(f"🔴 **{stage}**")
            else:
                st.info("No attack progression detected.")
            if tl_meta.pivot_count > 0:
                st.warning(f"⚡ {tl_meta.pivot_count} escalation pivot(s) detected")
        with c3:
            st.markdown("### 🧠 UEBA Insights")
            if pr.ueba_results:
                for u in sorted(pr.ueba_results,
                                key=lambda x: x.anomaly_score, reverse=True)[:3]:
                    score = u.anomaly_score
                    icon = "🔴" if score >= 70 else "🟡" if score >= 40 else "🟢"
                    st.markdown(f"{icon} **{u.ip}** — Score: {score:.0f}/100")
                    for a in (u.anomalies_found or [])[:2]:
                        st.caption(f"📋 {a[:80]}")
            else:
                st.info("No UEBA data available.")

        st.markdown("---")
        st.markdown("### 📈 Attack Progression Timeline")
        if pr.timeline.entries:
            st.info(f"**{get_progression_summary(pr.timeline)}**")
            fig, ax = plt.subplots(figsize=(12, 4))
            sev_map = {"Benign": 0, "Initial Access": 1, "Execution": 2,
                       "Privilege Escalation": 3, "Credential Access": 4}
            y = [sev_map.get(e.stage, 0) for e in pr.timeline.entries
                 if e.timestamp_rel != "time unknown"]
            x = list(range(len(y)))
            ax.plot(x, y, color="#58a6ff", linewidth=1.2, alpha=0.4)
            ax.scatter(x, y, c=["#2ea043" if v == 0 else "#f85149" for v in y],
                       s=60, zorder=5)
            ax.set_yticks([0, 1, 2, 3, 4])
            ax.set_yticklabels(["Benign", "Init.Access", "Execution",
                                "PrivEsc", "Cred.Access"], fontsize=8)
            ax.set_xlabel("Event Sequence", color="white")
            ax.set_facecolor("#0d1117")
            fig.patch.set_facecolor("#0d1117")
            ax.tick_params(colors="white")
            for s_ in ("top", "right"):
                ax.spines[s_].set_visible(False)
            st.pyplot(fig)
            plt.close()
        else:
            st.info("No timeline entries to display.")

        st.markdown("---")
        st.markdown("### 📊 Event Analysis")
        for entry in pr.timeline.entries[:15]:
            det = (pr.detection_results[entry.index]
                   if entry.index < len(pr.detection_results) else None)
            det_score = det.final_risk_score if det else 0
            icon = "🚨" if det_score >= 35 else "✅"
            pivot = " ⬆ PIVOT" if entry.is_pivot else ""
            header = (f"{icon} {entry.timestamp_rel} | {entry.alert_type} | "
                      f"{entry.stage} | Risk: {det_score}/100{pivot}")
            with st.expander(header, expanded=(det_score >= 60 and entry.index < 2)):
                a1, a2, a3, a4 = st.columns(4)
                a1.markdown(f"**Event ID:** `{entry.event_id}`")
                a2.markdown(f"**Source IP:** `{entry.source_ip}`")
                a3.markdown(f"**MITRE:** `{entry.technique_id or '—'}`")
                a4.markdown(f"**Dwell:** {entry.dwell_label}")
                if det:
                    st.caption(f"Rules: {det.rules_score:.0f}/100 | "
                               f"Anomaly: {det.anomaly_score:.0f}/100 | "
                               f"Baseline: {det.baseline_score:.0f}/100")
                    for r_ in det.rules_reasons:
                        st.markdown(f"  — {r_}")

        if inv.iocs:
            st.markdown("---")
            st.markdown("### 🔍 Indicators of Compromise")
            ioc_cols = st.columns(3)
            for i, ioc in enumerate(inv.iocs):
                ioc_type = ioc.type if hasattr(ioc, "type") else ioc.get("type", "?")
                ioc_value = ioc.value if hasattr(ioc, "value") else ioc.get("value", "?")
                ioc_note = ioc.note if hasattr(ioc, "note") else ioc.get("note", "")
                icon = ("🔴" if ioc_type == "ip" else
                        "🎯" if ioc_type == "technique" else "🟡")
                ioc_cols[i % 3].markdown(
                    f"{icon} **[{ioc_type.upper()}]** `{ioc_value}`\n\n_{ioc_note}_")


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — THREAT INTEL
# ════════════════════════════════════════════════════════════════════════════
with tab_intel:
    st.subheader("IP Threat Intelligence")
    st.caption("AbuseIPDB lookup (needs an API key in secrets/env) · "
               "private IPs are never queried.")

    lc, rc = st.columns([2, 1])
    with lc:
        lookup_ip = st.text_input("IP to investigate",
                                  placeholder="185.220.101.1", key="t3_ip")
    with rc:
        st.markdown("<br>", unsafe_allow_html=True)
        do_lookup = st.button("🔍 Investigate", type="primary",
                              use_container_width=True, key="t3_btn")

    if do_lookup and lookup_ip:
        with st.spinner(f"Querying threat intel for {lookup_ip} …"):
            ip_status_str, ip_score = check_ip_reputation(lookup_ip)
        st.markdown("---")
        m1, m2, m3 = st.columns(3)
        m1.metric("IP Address", lookup_ip)
        m2.metric("Abuse Score", f"{ip_score}/100")
        m3.metric("Verdict",
                  "🔴 Malicious" if ip_score >= 75 else
                  "🟡 Suspicious" if ip_score >= 30 else "🟢 Clean")
        st.markdown(f"**Full status:** {ip_status_str}")
        st.markdown("**🌐 Investigate further:**")
        o1, o2, o3, o4 = st.columns(4)
        o1.markdown(f"[AbuseIPDB](https://www.abuseipdb.com/check/{lookup_ip})")
        o2.markdown(f"[VirusTotal](https://www.virustotal.com/gui/ip-address/{lookup_ip})")
        o3.markdown(f"[Shodan](https://www.shodan.io/host/{lookup_ip})")
        o4.markdown(f"[Greynoise](https://viz.greynoise.io/ip/{lookup_ip})")
    else:
        st.markdown("---")
        st.markdown("### OSINT Reference")
        st.table({
            "Tool":    ["AbuseIPDB", "VirusTotal", "Shodan", "Greynoise"],
            "Purpose": ["IP abuse reports", "Multi-engine scan",
                        "Device intel", "Noise vs targeted"],
        })


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — TRIAGE QUEUE (persistent analyst workflow)
# ════════════════════════════════════════════════════════════════════════════
with tab_queue:
    st.subheader("📋 Triage Queue")
    st.caption("Persistent alert queue. Your triage decisions train the "
               "analyst-feedback model (Random Forest on behavioral features).")

    if "analyst_name" not in st.session_state:
        st.session_state.analyst_name = ""

    f1, f2, f3 = st.columns(3)
    with f1:
        q_status = st.selectbox("Status", ["open", "investigating", "all",
                                           "closed_true_positive",
                                           "closed_false_positive",
                                           "suppressed"], key="q_status")
    with f2:
        q_min = st.slider("Min risk", 0, 100, 0, key="q_min")
    with f3:
        st.markdown("<br>", unsafe_allow_html=True)
        analyst = st.text_input("Analyst name", key="analyst_name",
                                placeholder="e.g. Aman Ali")

    alerts = store.list_alerts(
        status=None if q_status == "all" else q_status, min_score=q_min)
    if not alerts:
        st.info("Queue is empty. Run the live feed or upload an EVTX to generate alerts.")
    else:
        for a in alerts:
            icon = {"Critical": "🔴", "High": "🟠",
                    "Medium": "🟡"}.get(a["severity"], "🟢")
            header = (f"{icon} #{a['id']} · {a['alert_type'][:55]} · "
                      f"risk {a['risk_score']} · {a['source_ip']} · "
                      f"`{a['status']}` · ×{a['event_count']}")
            with st.expander(header):
                c1, c2 = st.columns(2)
                c1.markdown(f"**First seen:** {a['first_seen'][:19]}")
                c1.markdown(f"**Last seen:** {a['last_seen'][:19]}")
                c2.markdown(f"**MITRE:** {', '.join(_json_loads(a['mitre'])[:3]) or '—'}")
                if a["notes"]:
                    st.markdown(f"**Notes:** {a['notes']}")
                if a["analyst"]:
                    st.caption(f"Last handled by {a['analyst']}")

                b1, b2, b3, b4 = st.columns(4)
                note = st.text_input("Note (optional)", key=f"note_{a['id']}",
                                     label_visibility="collapsed",
                                     placeholder="Note (optional)")
                acted = False
                if b1.button("🔍 Investigating", key=f"inv_{a['id']}"):
                    acted = store.set_status(a["id"], "investigating",
                                             analyst, note)
                if b2.button("✅ True Positive", key=f"tp_{a['id']}"):
                    acted = store.set_status(a["id"], "closed_true_positive",
                                             analyst, note)
                if b3.button("❌ False Positive", key=f"fp_{a['id']}"):
                    acted = store.set_status(a["id"], "closed_false_positive",
                                             analyst, note)
                if b4.button("🔕 Suppress", key=f"sup_{a['id']}"):
                    acted = store.set_status(a["id"], "suppressed",
                                             analyst, note)
                if acted:
                    retrained = feedback_model.maybe_retrain()
                    if retrained:
                        st.success("Analyst-feedback model retrained on new labels.")
                    st.rerun()

    st.markdown("---")
    st.markdown("### 🧠 Analyst-Feedback Model")
    fb_info = feedback_model.model_info()
    if fb_info.get("available"):
        st.success(f"🟢 Trained on {fb_info['labels_at_train']} analyst decisions. "
                   f"Similar past alerts now adjust prioritization (±8).")
        if st.button("🔄 Retrain now", key="fb_retrain"):
            try:
                info = feedback_model.train()
                st.success(f"Retrained on {info['labels']} labels "
                           f"(TP={info['tp']}, FP={info['fp']}).")
            except ValueError as e:
                st.warning(str(e))
    else:
        n_labels = len(store.labeled_events())
        st.info(f"⚪ Cold start — {n_labels}/20 analyst decisions needed. "
                f"Triage alerts above as true/false positives to train it. "
                f"Labels are your real decisions; the model learns which "
                f"behavioral patterns you confirm.")


# AUTO-REFRESH — at the END so the page renders first (no blocking sleep up top)
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
