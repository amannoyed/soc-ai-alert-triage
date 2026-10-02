"""
simulator.py
════════════
Explicitly-synthetic live attack simulator for DEMO purposes.

This generates fake-but-plausible attack traffic so the dashboard's
real-time path can be demonstrated without real logs. Every event it
emits is marked "synthetic": True. It is NEVER presented as real data —
the UI labels simulator-driven views as "SIMULATED FEED".

For real monitoring, point WatchFolder (ingest.py) at a folder and drop
in .evtx / .csv logs instead.

Scenarios:
  - "brute_force_escalation": password spray → brute force → successful
    login → privilege escalation → credential dumping
  - "malware_drop": suspicious process chain ending in lsass access
  - "mixed_noise": mostly benign logins with occasional attack bursts
  - "slow_credential_stuffing": low-and-slow 4625 trickle from rotating
    exit nodes, then one success (tests the slow-burn detector)
  - "lateral_movement": foothold → pivots across internal hosts →
    privilege escalation → credential dumping (tests per-IP chains)
  - "insider_off_hours": off-hours logins from an internal host, then
    privilege escalation (tests hour-of-day anomaly scoring)

Usage:
    sim = AttackSimulator("brute_force_escalation")
    while True:
        for event in sim.poll():   # events since last poll
            handle(event)
        time.sleep(2)
"""

import random
from datetime import datetime, timezone, timedelta

random.seed()


def _now():
    return datetime.now(timezone.utc)


# Each scenario: list of (delay_seconds_from_prev, event_dict_template)
def _scenario_brute_force_escalation(attacker_ip: str):
    t = _now() - timedelta(minutes=6)
    events = []
    # Password spray: a few attempts, minutes apart
    for i in range(4):
        t += timedelta(minutes=2)
        events.append((t, {
            "event_id": "4625", "alert_type": "Password Spray",
            "failed_logins": 6, "source_ip": attacker_ip,
            "location": "Russia", "device": "Linux", "process_risk": 0}))
    # Brute force burst
    for i in range(6):
        t += timedelta(seconds=20)
        events.append((t, {
            "event_id": "4625", "alert_type": "Brute Force",
            "failed_logins": 12, "source_ip": attacker_ip,
            "location": "Russia", "device": "Linux", "process_risk": 0}))
    # Successful login, then privilege escalation
    t += timedelta(minutes=1)
    events.append((t, {
        "event_id": "4624", "alert_type": "Normal Login",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": "Russia", "device": "Linux", "process_risk": 0}))
    t += timedelta(seconds=45)
    events.append((t, {
        "event_id": "4672", "alert_type": "Privilege Escalation",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": "Russia", "device": "Linux", "process_risk": 0}))
    # Credential dumping via Sysmon-style process access
    t += timedelta(seconds=30)
    events.append((t, {
        "event_id": "10", "alert_type": "Credential Dumping",
        "failed_logins": 0, "source_ip": None,
        "location": "Unknown", "device": "Windows", "process_risk": 1}))
    return events


def _scenario_malware_drop(attacker_ip: str):
    t = _now() - timedelta(minutes=4)
    events = []
    t += timedelta(seconds=30)
    events.append((t, {
        "event_id": "1", "alert_type": "Malware Execution",
        "failed_logins": 0, "source_ip": None,
        "location": "Unknown", "device": "Windows", "process_risk": 1}))
    t += timedelta(seconds=50)
    events.append((t, {
        "event_id": "4698", "alert_type": "Suspicious Activity",
        "failed_logins": 0, "source_ip": None,
        "location": "Unknown", "device": "Windows", "process_risk": 0}))
    t += timedelta(minutes=1)
    events.append((t, {
        "event_id": "3", "alert_type": "Suspicious Activity",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": "Netherlands", "device": "Windows", "process_risk": 0}))
    return events


def _scenario_mixed_noise():
    t = _now() - timedelta(minutes=10)
    events = []
    users = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.20"]
    for i in range(14):
        t += timedelta(seconds=random.randint(20, 50))
        events.append((t, {
            "event_id": "4624", "alert_type": "Normal Login",
            "failed_logins": random.choice([0, 0, 0, 1, 2]),
            "source_ip": random.choice(users),
            "location": random.choice(["India", "India", "US", "UK"]),
            "device": "Windows", "process_risk": 0}))
    # occasional burst
    t += timedelta(seconds=30)
    for i in range(5):
        t += timedelta(seconds=15)
        events.append((t, {
            "event_id": "4625", "alert_type": "Brute Force",
            "failed_logins": 9, "source_ip": "185.220.101.1",
            "location": "China", "device": "Linux", "process_risk": 0}))
    return events


def _scenario_slow_credential_stuffing(attacker_ip: str):
    """Low-and-slow: 1-2 failed logins per event, rotating exit nodes."""
    t = _now() - timedelta(minutes=40)
    events = []
    exits = ["Russia", "Netherlands", "Brazil", "Singapore"]
    for i in range(12):
        t += timedelta(minutes=random.randint(2, 4))
        events.append((t, {
            "event_id": "4625", "alert_type": "Password Spray",
            "failed_logins": random.choice([1, 1, 2]),
            "source_ip": attacker_ip,
            "location": exits[i % len(exits)],
            "device": "Linux", "process_risk": 0}))
    t += timedelta(minutes=3)
    events.append((t, {
        "event_id": "4624", "alert_type": "Normal Login",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": exits[-1], "device": "Linux", "process_risk": 0}))
    return events


def _scenario_lateral_movement(attacker_ip: str):
    """Foothold → pivots across internal hosts → escalation → dumping."""
    t = _now() - timedelta(minutes=14)
    events = []
    t += timedelta(minutes=2)
    events.append((t, {
        "event_id": "4624", "alert_type": "Normal Login",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": "Russia", "device": "WS-101", "process_risk": 0}))
    for host in ["WS-102", "WS-103", "SRV-DB-01"]:
        t += timedelta(minutes=2)
        events.append((t, {
            "event_id": "4624", "alert_type": "Suspicious Activity",
            "failed_logins": 0, "source_ip": attacker_ip,
            "location": "Russia", "device": host, "process_risk": 0}))
    t += timedelta(minutes=1)
    events.append((t, {
        "event_id": "4672", "alert_type": "Privilege Escalation",
        "failed_logins": 0, "source_ip": attacker_ip,
        "location": "Russia", "device": "SRV-DB-01", "process_risk": 0}))
    t += timedelta(seconds=40)
    events.append((t, {
        "event_id": "10", "alert_type": "Credential Dumping",
        "failed_logins": 0, "source_ip": None,
        "location": "Unknown", "device": "SRV-DB-01", "process_risk": 1}))
    return events


def _scenario_insider_off_hours():
    """Off-hours logins from an internal host, then escalation."""
    now = _now()
    t = now.replace(hour=2, minute=30, second=0, microsecond=0)
    if t > now:  # 02:30 hasn't happened yet today → use yesterday's
        t -= timedelta(days=1)
    events = []
    ip = "192.168.1.50"
    for _ in range(3):
        t += timedelta(minutes=25)
        events.append((t, {
            "event_id": "4624", "alert_type": "Normal Login",
            "failed_logins": 0, "source_ip": ip,
            "location": "India", "device": "WS-FIN-07", "process_risk": 0}))
    t += timedelta(minutes=20)
    events.append((t, {
        "event_id": "4672", "alert_type": "Privilege Escalation",
        "failed_logins": 0, "source_ip": ip,
        "location": "India", "device": "WS-FIN-07", "process_risk": 0}))
    t += timedelta(minutes=15)
    events.append((t, {
        "event_id": "4663", "alert_type": "Suspicious Activity",
        "failed_logins": 0, "source_ip": ip,
        "location": "India", "device": "WS-FIN-07", "process_risk": 0}))
    return events


SCENARIOS = {
    "brute_force_escalation": _scenario_brute_force_escalation,
    "malware_drop":           _scenario_malware_drop,
    "mixed_noise":            _scenario_mixed_noise,
    "slow_credential_stuffing": _scenario_slow_credential_stuffing,
    "lateral_movement":       _scenario_lateral_movement,
    "insider_off_hours":      _scenario_insider_off_hours,
}


class AttackSimulator:
    """
    Emits a scripted attack scenario as a timed event stream.

    poll() returns events whose scheduled time has arrived since the last
    poll. When the scenario is exhausted, poll() returns [] (finished=True).
    Call reset() to replay.
    """

    def __init__(self, scenario: str = "brute_force_escalation",
                 attacker_ip: str = "45.33.32.1"):
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario {scenario!r}. "
                             f"Choose from {list(SCENARIOS)}")
        self.scenario = scenario
        self.attacker_ip = attacker_ip
        self.reset()

    def reset(self):
        builder = SCENARIOS[self.scenario]
        try:
            script = builder(self.attacker_ip)
        except TypeError:
            script = builder()
        self._script = [(ts, evt) for ts, evt in script]
        self._cursor = 0
        self.finished = False

    def poll(self) -> list[dict]:
        """Events whose time has come since the last poll."""
        if self.finished:
            return []
        now = _now()
        out = []
        while self._cursor < len(self._script):
            ts, evt = self._script[self._cursor]
            if ts > now:
                break
            event = dict(evt)
            event["timestamp"] = ts.isoformat()
            event["synthetic"] = True   # never misrepresent demo traffic
            out.append(event)
            self._cursor += 1
        if self._cursor >= len(self._script):
            self.finished = True
        return out


if __name__ == "__main__":
    import time
    print("Simulator self-test\n" + "=" * 40)
    sim = AttackSimulator("brute_force_escalation")
    # Fast-forward: pretend time has passed by polling in a loop
    total = []
    # Drain by temporarily shifting script times into the past
    sim._script = [(_now() - timedelta(seconds=i), e)
                   for i, (_, e) in enumerate(reversed(sim._script))]
    sim._script.reverse()
    total.extend(sim.poll())
    print(f"scenario={sim.scenario} events={len(total)} "
          f"finished={sim.finished} all_synthetic={all(e['synthetic'] for e in total)}")
    print("types:", [e["alert_type"] for e in total])
