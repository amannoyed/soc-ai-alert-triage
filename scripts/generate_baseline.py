"""
scripts/generate_baseline.py
════════════════════════════
Generate a synthetic BENIGN baseline event set for training the
unsupervised anomaly detector.

IMPORTANT — what this is and isn't:
  - This is DEMO data: plausible benign Windows/Sysmon-style activity with
    realistic time-of-day, event-mix, and failure-count distributions.
  - It is NOT real log data and NOT attack data. The anomaly detector is
    unsupervised: it learns "normal" from this baseline and flags
    deviations. No labels are used anywhere in training.
  - For production use, replace this file's output with your own historical
    benign logs in the same CSV schema.

Schema: event_id, timestamp, alert_type, failed_logins, source_ip,
        location, device, process_risk

Run:  python scripts/generate_baseline.py [--n 2000]
Out:  data/baseline_benign.csv
"""

import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

random.seed(42)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT  = os.path.join(BASE, "data", "baseline_benign.csv")

# Benign event mix: (event_id, alert_type, weight)
BENIGN_MIX = [
    ("4624", "Normal Login",        45),   # successful logon
    ("1",    "Suspicious Activity", 25),   # Sysmon process create (usually benign)
    ("3",    "Suspicious Activity", 15),   # Sysmon network connection
    ("4688", "Suspicious Activity", 10),   # Security process created
    ("11",   "Suspicious Activity",  5),   # Sysmon file created
]

LOCATIONS = [("India", 40), ("US", 25), ("UK", 12), ("Germany", 10),
             ("Brazil", 5), ("China", 4), ("Russia", 2), ("North Korea", 2)]
DEVICES   = [("Windows", 70), ("Linux", 20), ("MacOS", 7), ("Android", 3)]

PRIVATE_IPS = [f"192.168.1.{i}" for i in range(2, 120)] + \
              [f"10.0.0.{i}" for i in range(2, 60)]


def _weighted(choices):
    items, weights = zip(*choices)
    return random.choices(items, weights=weights, k=1)[0]


def _biz_hour():
    """Realistic hour: heavy 8-18, light evenings, sparse nights."""
    r = random.random()
    if r < 0.72:
        return random.randint(8, 17)
    if r < 0.90:
        return random.choice([7, 18, 19, 20, 21])
    return random.randint(0, 6)


def generate(n: int) -> list[dict]:
    rows = []
    start = datetime(2026, 1, 5, 0, 0, tzinfo=timezone.utc)
    for _ in range(n):
        event_id, alert_type = _weighted(
            [((e, a), w) for e, a, w in BENIGN_MIX])
        day = random.randint(0, 13)
        hour = _biz_hour()
        ts = start + timedelta(days=day, hours=hour,
                               minutes=random.randint(0, 59),
                               seconds=random.randint(0, 59))
        # Benign failure counts: almost always tiny, occasional blip
        r = random.random()
        failed = 0 if r < 0.80 else (random.randint(1, 3) if r < 0.95
                                     else random.randint(4, 7))
        rows.append({
            "event_id":      event_id,
            "timestamp":     ts.isoformat(),
            "alert_type":    alert_type,
            "failed_logins": failed,
            "source_ip":     random.choice(PRIVATE_IPS),
            "location":      _weighted(LOCATIONS),
            "device":        _weighted(DEVICES),
            "process_risk":  0,
        })
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    args = ap.parse_args()

    rows = generate(args.n)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} benign baseline events → {OUT}")
    print("NOTE: synthetic demo data for unsupervised training only.")


if __name__ == "__main__":
    main()
