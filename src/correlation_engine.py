def correlate_events(events):
    alerts = []

    failed_total = sum(e.get("failed_logins", 0) for e in events)
    suspicious = [e for e in events if e.get("alert_type") != "Normal Login"]

    suspicious_count = len(suspicious)

    # 🔥 Strong brute force
    if failed_total > 40:
        alerts.append({
            "type": "Brute Force Attack",
            "severity": "High",
            "description": f"{failed_total} suspicious attempts detected"
        })

    # 🔥 Multi-stage attack detection
    if suspicious_count >= 3:
        alerts.append({
            "type": "Multi-stage Attack",
            "severity": "Critical",
            "description": f"{suspicious_count} suspicious events chained together"
        })

    # 🔥 Malware cluster
    malware_events = [e for e in events if e.get("alert_type") == "Malware Execution"]
    if len(malware_events) >= 2:
        alerts.append({
            "type": "Malware Campaign Detected",
            "severity": "Critical",
            "description": "Repeated malware execution observed"
        })

    if not alerts:
        alerts.append({
            "type": "Low Activity",
            "severity": "Low",
            "description": "No major attack pattern"
        })

    return alerts