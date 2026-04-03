def correlate_events(events):
    alerts = []

    failed_login_count = 0
    suspicious_process = 0

    for event in events:
        failed_login_count += event.get("failed_logins", 0)

        if event.get("alert_type") == "Suspicious Activity":
            suspicious_process += 1

    # 🔥 Rule 1 — Brute force
    if failed_login_count > 15:
        alerts.append({
            "type": "Brute Force Attack",
            "severity": "High",
            "description": "Multiple failed login attempts detected"
        })

    # 🔥 Rule 2 — Attack chain
    if failed_login_count > 10 and suspicious_process > 2:
        alerts.append({
            "type": "Possible Account Compromise",
            "severity": "Critical",
            "description": "Failed logins followed by suspicious activity"
        })

    # 🔥 Rule 3 — Noise filtering
    if failed_login_count < 5 and suspicious_process == 0:
        alerts.append({
            "type": "Normal Activity",
            "severity": "Low",
            "description": "No significant threat pattern detected"
        })

    return alerts