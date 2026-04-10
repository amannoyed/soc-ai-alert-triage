"""
ueba_engine.py
══════════════
User and Entity Behavior Analytics (UEBA)

Tracks per-IP behavioral profiles:
  - Login frequency over time windows
  - Failed attempt history and spikes
  - Country changes (impossible travel proxy)
  - Time-of-day patterns (off-hours detection)
  - Rolling averages vs current behaviour

All profiles are stored in-memory during a session.
Call UEBAEngine.load() / .save() for persistence.
"""

import os
import json
import math
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROFILE_PATH = os.path.join(_BASE, "model", "ueba_profiles.json")


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BehaviorEvent:
    timestamp:    str
    failed_logins: int
    alert_type:   str
    location:     str
    device:       str

    @classmethod
    def now(cls, failed_logins: int = 0, alert_type: str = "Normal Login",
            location: str = "Unknown", device: str = "Unknown") -> "BehaviorEvent":
        return cls(
            timestamp     = datetime.now(timezone.utc).isoformat(),
            failed_logins = failed_logins,
            alert_type    = alert_type,
            location      = location,
            device        = device,
        )


@dataclass
class IPProfile:
    ip:                   str
    first_seen:           str   = ""
    last_seen:            str   = ""
    total_events:         int   = 0
    total_failed_logins:  int   = 0
    locations_seen:       list  = field(default_factory=list)
    devices_seen:         list  = field(default_factory=list)
    alert_types_seen:     list  = field(default_factory=list)
    # Rolling window: last 50 events kept
    recent_events:        list  = field(default_factory=list)
    # Baseline (built after ≥5 events)
    avg_failed_per_event: float = 0.0
    typical_hours:        list  = field(default_factory=list)   # [0..23]
    primary_location:     str   = "Unknown"
    primary_device:       str   = "Unknown"


@dataclass
class UEBAResult:
    ip:                str
    anomaly_score:     float         # 0–100
    anomaly_label:     str
    behavior_summary:  str
    anomalies_found:   list[str]     # human-readable findings
    is_new_ip:         bool
    profile_age_events: int
    spike_detected:    bool
    new_location:      bool
    off_hours_access:  bool
    timestamp:         str

    def to_dict(self) -> dict:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
# UEBA ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Thresholds (tweak to adjust sensitivity)
_SPIKE_MULTIPLIER      = 3.0   # current > avg × this → spike
_SPIKE_ABS_MIN         = 8     # minimum absolute count to call a spike
_OFF_HOURS             = set(range(0, 6)) | {22, 23}   # midnight–6 AM + 10–11 PM
_NEW_IP_RISK           = 15    # score added for first-ever seen IP
_SPIKE_RISK            = 35    # score added for activity spike
_NEW_LOCATION_RISK     = 25    # score added for new country
_OFF_HOURS_RISK        = 15    # score added for off-hours access
_HIGH_FAIL_RISK        = 20    # score added when raw failed count is very high
_REPEAT_ATTACKER_RISK  = 20    # score added if IP has prior threat history


class UEBAEngine:
    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}

    # ── Persistence ──────────────────────────────────────────────────────────

    def save(self, path: str = _PROFILE_PATH) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {ip: asdict(p) for ip, p in self._profiles.items()}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str = _PROFILE_PATH) -> "UEBAEngine":
        if not os.path.exists(path):
            return self
        with open(path) as f:
            raw = json.load(f)
        for ip, d in raw.items():
            p = IPProfile(ip=ip)
            for k, v in d.items():
                setattr(p, k, v)
            self._profiles[ip] = p
        return self

    # ── Profile management ───────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> IPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(
                ip         = ip,
                first_seen = datetime.now(timezone.utc).isoformat(),
            )
        return self._profiles[ip]

    def _update_profile(self, profile: IPProfile, event: BehaviorEvent) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        profile.last_seen           = now_str
        profile.total_events       += 1
        profile.total_failed_logins += event.failed_logins

        # Locations
        if event.location not in profile.locations_seen:
            profile.locations_seen.append(event.location)

        # Devices
        if event.device not in profile.devices_seen:
            profile.devices_seen.append(event.device)

        # Alert types
        if event.alert_type not in profile.alert_types_seen:
            profile.alert_types_seen.append(event.alert_type)

        # Rolling window (last 50)
        profile.recent_events.append(asdict(event))
        if len(profile.recent_events) > 50:
            profile.recent_events.pop(0)

        # Rebuild baseline if enough data
        if profile.total_events >= 5:
            self._rebuild_baseline(profile)

    def _rebuild_baseline(self, profile: IPProfile) -> None:
        events = profile.recent_events
        if not events:
            return
        fails = [e["failed_logins"] for e in events]
        profile.avg_failed_per_event = sum(fails) / len(fails)

        hours = []
        for e in events:
            try:
                dt = datetime.fromisoformat(e["timestamp"])
                hours.append(dt.hour)
            except Exception:
                pass
        profile.typical_hours = list(set(hours))

        from collections import Counter
        if profile.locations_seen:
            profile.primary_location = Counter(
                e["location"] for e in events
            ).most_common(1)[0][0]
        if profile.devices_seen:
            profile.primary_device = Counter(
                e["device"] for e in events
            ).most_common(1)[0][0]

    # ── Anomaly detection ────────────────────────────────────────────────────

    def _detect_spike(self, profile: IPProfile,
                      current_failed: int) -> tuple[bool, str]:
        if profile.total_events < 5 or profile.avg_failed_per_event == 0:
            return False, ""
        ratio = current_failed / profile.avg_failed_per_event
        if current_failed >= _SPIKE_ABS_MIN and ratio >= _SPIKE_MULTIPLIER:
            avg = profile.avg_failed_per_event
            return True, (
                f"Activity spike detected — IP usually generates "
                f"{avg:.1f} failed attempts, now {current_failed} "
                f"({ratio:.1f}× above baseline)"
            )
        return False, ""

    def _detect_new_location(self, profile: IPProfile,
                             location: str) -> tuple[bool, str]:
        if profile.total_events < 3:
            return False, ""
        if location != profile.primary_location and location not in profile.locations_seen:
            return True, (
                f"New location detected — IP previously seen only from "
                f"'{profile.primary_location}', now connecting from '{location}'"
            )
        return False, ""

    def _detect_off_hours(self, event: BehaviorEvent,
                          profile: IPProfile) -> tuple[bool, str]:
        try:
            dt   = datetime.fromisoformat(event.timestamp)
            hour = dt.hour
        except Exception:
            return False, ""
        if hour in _OFF_HOURS:
            return True, (
                f"Off-hours access at {hour:02d}:00 UTC "
                f"(outside business hours 06–22)"
            )
        return False, ""

    def _detect_repeat_attacker(self, profile: IPProfile) -> tuple[bool, str]:
        threat_types = {"Brute Force", "Credential Stuffing", "Password Spray",
                        "Malware Execution", "Credential Dumping",
                        "Privilege Escalation", "Suspicious Activity"}
        prior = set(profile.alert_types_seen) & threat_types
        if len(prior) >= 2:
            return True, (
                f"Repeat attacker — IP has prior history of: "
                f"{', '.join(sorted(prior))}"
            )
        return False, ""

    # ── Main analysis ────────────────────────────────────────────────────────

    def analyze(self, ip: str, event: BehaviorEvent) -> UEBAResult:
        profile  = self._get_or_create(ip)
        is_new   = profile.total_events == 0

        # Run detectors BEFORE updating profile (so we compare against history)
        spike_hit,    spike_msg    = self._detect_spike(profile, event.failed_logins)
        new_loc_hit,  new_loc_msg  = self._detect_new_location(profile, event.location)
        off_hrs_hit,  off_hrs_msg  = self._detect_off_hours(event, profile)
        repeat_hit,   repeat_msg   = self._detect_repeat_attacker(profile)

        # Update profile with current event
        self._update_profile(profile, event)

        # Score
        score        = 0.0
        anomalies    = []

        if is_new:
            score += _NEW_IP_RISK
            anomalies.append("First time this IP has been observed")

        if spike_hit:
            score += _SPIKE_RISK
            anomalies.append(spike_msg)

        if new_loc_hit:
            score += _NEW_LOCATION_RISK
            anomalies.append(new_loc_msg)

        if off_hrs_hit:
            score += _OFF_HOURS_RISK
            anomalies.append(off_hrs_msg)

        if repeat_hit:
            score += _REPEAT_ATTACKER_RISK
            anomalies.append(repeat_msg)

        if event.failed_logins >= 20:
            score += _HIGH_FAIL_RISK
            anomalies.append(
                f"Absolute failed login count is very high ({event.failed_logins})")

        score = min(round(score, 1), 100.0)

        # Label
        if score >= 70:
            label = "🔴 High Anomaly"
        elif score >= 40:
            label = "🟡 Moderate Anomaly"
        elif score > 0:
            label = "🟠 Low Anomaly"
        else:
            label = "🟢 Normal Behavior"

        # Human-readable summary
        summary = self._build_summary(ip, profile, event, anomalies, score)

        return UEBAResult(
            ip                  = ip,
            anomaly_score       = score,
            anomaly_label       = label,
            behavior_summary    = summary,
            anomalies_found     = anomalies,
            is_new_ip           = is_new,
            profile_age_events  = profile.total_events,
            spike_detected      = spike_hit,
            new_location        = new_loc_hit,
            off_hours_access    = off_hrs_hit,
            timestamp           = datetime.now(timezone.utc).isoformat(),
        )

    def _build_summary(self, ip: str, profile: IPProfile,
                       event: BehaviorEvent, anomalies: list,
                       score: float) -> str:
        age   = profile.total_events
        avg   = profile.avg_failed_per_event
        locs  = ", ".join(profile.locations_seen) or "unknown"

        if age <= 1:
            base = f"IP {ip} is new — no behavioral history available."
        else:
            base = (
                f"IP {ip} has {age} recorded events. "
                f"Avg failed logins: {avg:.1f}. "
                f"Locations seen: {locs}."
            )

        if not anomalies:
            return base + " Behavior consistent with historical baseline."

        finding_str = " | ".join(anomalies)
        return f"{base} ⚠️ Anomalies: {finding_str}"

    # ── Utility ──────────────────────────────────────────────────────────────

    def get_profile(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def all_profiles(self) -> dict[str, IPProfile]:
        return dict(self._profiles)

    def top_risky_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """Return top N IPs by total failed logins."""
        ranked = sorted(
            self._profiles.items(),
            key=lambda x: x[1].total_failed_logins,
            reverse=True,
        )
        return [(ip, p.total_failed_logins) for ip, p in ranked[:n]]


# ── Module-level singleton ─────────────────────────────────────────────────────
_engine = UEBAEngine().load()


def analyze_ip(ip: str, event: BehaviorEvent) -> UEBAResult:
    """Convenience function using the module singleton."""
    return _engine.analyze(ip, event)


def analyze_from_log(log: dict) -> UEBAResult:
    """
    Build a BehaviorEvent from a parsed log dict and run UEBA analysis.
    Expected keys: source_ip, failed_logins, alert_type, location, device
    """
    ip = log.get("source_ip", "0.0.0.0")
    event = BehaviorEvent.now(
        failed_logins = log.get("failed_logins", 0),
        alert_type    = log.get("alert_type",   "Normal Login"),
        location      = log.get("location",     "Unknown"),
        device        = log.get("device",        "Unknown"),
    )
    return _engine.analyze(ip, event)


def get_engine() -> UEBAEngine:
    return _engine


def persist():
    """Save current profiles to disk."""
    _engine.save()


if __name__ == "__main__":
    print("UEBA Engine — Self-Test\n" + "=" * 50)

    # Simulate: IP builds a clean history, then spikes
    from datetime import timezone
    test_ip = "45.33.32.1"

    # Build baseline — 8 normal events
    for i in range(8):
        evt = BehaviorEvent.now(failed_logins=2, alert_type="Normal Login",
                                location="India", device="Windows")
        _engine.analyze(test_ip, evt)

    # Now spike
    spike_evt = BehaviorEvent.now(failed_logins=30, alert_type="Brute Force",
                                  location="Russia", device="Linux")
    result = _engine.analyze(test_ip, spike_evt)

    print(f"\nIP: {result.ip}")
    print(f"Score: {result.anomaly_score}/100 — {result.anomaly_label}")
    print(f"Summary: {result.behavior_summary}")
    print(f"Spike: {result.spike_detected} | New loc: {result.new_location}")
    print("Anomalies:")
    for a in result.anomalies_found:
        print(f"  • {a}")
