def correlate_events(events):
    alerts = []

    failed_total = sum(e.get("failed_logins", 0) for e in events)

    if failed_total > 50:
        alerts.append({
            "type": "Brute Force Attack",
            "severity": "High",
            "description": "Multiple login attempts detected"
        })

    if len(events) >= 3:
        alerts.append({
            "type": "Multi-stage Attack",
            "severity": "Critical",
            "description": "Attack chain behavior detected"
        })

    if not alerts:
        alerts.append({
            "type": "Low Activity",
            "severity": "Low",
            "description": "No major threats"
        })

    return alerts