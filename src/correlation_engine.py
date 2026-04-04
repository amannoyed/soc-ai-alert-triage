def correlate_events(events):
    alerts = []

    failed_total = sum(e.get("failed_logins", 0) for e in events)
    suspicious_count = sum(1 for e in events if e.get("alert_type") != "Normal Login")

    # 🔥 Brute force pattern
    if failed_total > 50:
        alerts.append({
            "type": "Brute Force Attack",
            "severity": "High",
            "description": f"Multiple failed login attempts detected ({failed_total})"
        })

    # 🔥 Attack chain detection
    if suspicious_count > 3:
        alerts.append({
            "type": "Multi-stage Attack Detected",
            "severity": "Critical",
            "description": f"{suspicious_count} suspicious events detected"
        })

    # 🔥 Fallback
    if not alerts:
        alerts.append({
            "type": "Low Activity",
            "severity": "Low",
            "description": "No strong attack patterns detected"
        })

    return alerts