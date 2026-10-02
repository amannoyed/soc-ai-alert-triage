"""
predict.py
══════════
Threat-intel helpers: IP reputation (AbuseIPDB) and MITRE ATT&CK mapping.

NOTE: the old ML prediction path (predict_alert / calculate_risk_score /
GradientBoosting) was removed in the honest-engine rewrite — it trained on
labels that were a deterministic function of alert_type. Per-event scoring
now lives in detection_engine.py; this module keeps only intel lookups.
"""

import os
import requests

# ── API Key ───────────────────────────────────────────────────────────────────
# Set via Streamlit secrets or environment variable. Never hardcoded.

def _get_api_key():
    try:
        import streamlit as st
        return st.secrets.get("ABUSEIPDB_API_KEY", "")
    except Exception:
        return os.getenv("ABUSEIPDB_API_KEY", "")


# ── IP Reputation ─────────────────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> tuple[str, int]:
    """
    Returns (status_string, abuse_score 0-100).

    Uses AbuseIPDB when a key is configured, otherwise reports that no
    live lookup was possible. Private/loopback ranges are never queried.
    """
    if not ip or ip == "unknown":
        return "⚪ No IP observed", 0
    if ip.startswith(("192.168.", "10.", "172.", "127.", "0.", "::1")):
        return "🟢 Internal / loopback IP", 0

    api_key = _get_api_key()
    if not api_key:
        return "⚪ No threat-intel key configured (clean by default)", 0

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        data = resp.json()
        score = int(data["data"]["abuseConfidenceScore"])
        country = data["data"].get("countryCode", "??")

        if score >= 75:
            return f"🔴 Malicious IP [{country}] (AbuseIPDB score: {score})", score
        elif score >= 30:
            return f"🟡 Suspicious IP [{country}] (AbuseIPDB score: {score})", score
        return f"🟢 Clean IP [{country}] (AbuseIPDB score: {score})", score
    except Exception as e:
        return f"⚠️ Lookup failed ({type(e).__name__})", 0


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
# Single source of truth lives in mitre.py; kept here for import compatibility.

import mitre as _mitre

MITRE_MAP = {k: v for k, v in _mitre.ALERT_TECHNIQUES.items()}


def map_mitre(alert_type: str) -> list[str]:
    return _mitre.techniques_for_alert(alert_type)
