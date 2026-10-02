"""
features.py
═══════════
Honest behavioral feature extraction for the detection engine.

Every feature here is derived from OBSERVABLE event properties only:
event ID, timestamp, IP class, and parser-extracted process indicators.

Deliberately EXCLUDED (these caused the old label-leakage tautology):
  - alert_type one-hot encoding (the old model just memorized the label)
  - any feature computed from ground-truth labels
  - "threat rates" derived from labeled data

Feature vector (all numeric, documented ranges):
  hour_sin, hour_cos  cyclic encoding of event hour (0/0 when time unknown)
  dow               day of week 0=Monday..6=Sunday (-1 when unknown)
  is_off_hours      1 when event hour in 00-05 or 22-23 UTC
  failed_logins_log log1p of failed-login count (real counts only)
  event_risk        heuristic severity weight for the event category (0-50)
  process_risk      1 when parser flagged malicious process/suspicious cmdline
  src_external      1 public IP, 0 private/loopback, 0.5 unknown
  has_ip            1 when a source IP was actually observed
"""

import math
from datetime import datetime, timezone

# ── Heuristic per-event severity weights ──────────────────────────────────────
# Domain-knowledge weights (documented, tunable). These are INPUTS to detection,
# not learned from labels — equivalent to a SOC analyst's triage heuristics.
EVENT_RISK = {
    "4625": 25,   # Security: failed logon
    "4624": 0,    # Security: successful logon (benign)
    "4648": 12,   # Security: explicit-credential logon
    "4672": 30,   # Security: special privileges assigned
    "4688": 10,   # Security: process created
    "4698": 15,   # Security: scheduled task created
    "4732": 25,   # Security: member added to privileged group
    "1":    8,    # Sysmon: process created
    "3":    6,    # Sysmon: network connection
    "7":    10,   # Sysmon: image loaded
    "10":   35,   # Sysmon: process access (often lsass)
    "11":   8,    # Sysmon: file created
}

_OFF_HOURS = set(range(0, 6)) | {22, 23}

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "dow", "is_off_hours",
    "failed_logins_log", "event_risk", "process_risk",
    "src_external", "has_ip",
]


def _parse_hour_dow(ts):
    """Return (hour, dow) from an ISO timestamp, or (None, None)."""
    if not ts:
        return None, None
    try:
        dt = datetime.fromisoformat(str(ts))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.hour, dt.weekday()
    except Exception:
        return None, None


def _ip_class(ip):
    """Classify an IP string: 'private', 'public', or 'unknown'."""
    if not ip or ip == "unknown":
        return "unknown"
    ip = str(ip).strip()
    if (ip.startswith(("10.", "192.168.", "127.", "0."))
            or ip.startswith("172.")
            and len(ip.split(".")) == 4
            and ip.split(".")[1].isdigit()
            and 16 <= int(ip.split(".")[1]) <= 31):
        return "private"
    if ip == "::1":
        return "private"
    return "public"


def extract_features(log: dict) -> dict:
    """
    Build the honest behavioral feature vector for one parsed log dict.

    Expected keys (all optional — missing values degrade gracefully):
      event_id, timestamp (ISO-8601), alert_type, failed_logins,
      source_ip, location, device, process_risk (0/1 from parser)
    """
    event_id = str(log.get("event_id", ""))
    hour, dow = _parse_hour_dow(log.get("timestamp"))

    if hour is None:
        hour_sin, hour_cos, is_off = 0.0, 0.0, 0
        dow_val = -1
    else:
        rad = 2 * math.pi * hour / 24
        hour_sin, hour_cos = math.sin(rad), math.cos(rad)
        is_off = 1 if hour in _OFF_HOURS else 0
        dow_val = dow if dow is not None else -1

    try:
        failed = max(0, int(log.get("failed_logins") or 0))
    except (TypeError, ValueError):
        failed = 0

    ip_kind = _ip_class(log.get("source_ip"))

    return {
        "hour_sin":          round(hour_sin, 4),
        "hour_cos":          round(hour_cos, 4),
        "dow":               dow_val,
        "is_off_hours":      is_off,
        "failed_logins_log": round(math.log1p(failed), 4),
        "event_risk":        float(EVENT_RISK.get(event_id, 5)),
        "process_risk":      1 if log.get("process_risk") else 0,
        "src_external":      {"public": 1.0, "private": 0.0,
                              "unknown": 0.5}[ip_kind],
        "has_ip":            1 if ip_kind != "unknown" else 0,
    }


def to_vector(feat: dict) -> list:
    """Ordered numeric vector for sklearn."""
    return [float(feat[name]) for name in FEATURE_NAMES]
