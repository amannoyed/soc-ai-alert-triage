def correlate_events(events: list[dict]) -> list[dict]:
    alerts = []

    total_failed = sum(e.get("failed_logins", 0) for e in events)
    alert_types = [e.get("alert_type", "Normal Login") for e in events]

    threat_events = [e for e in events if e.get("alert_type") != "Normal Login"]
    unique_ips = {e.get("source_ip", "") for e in events if e.get("source_ip")}
    unique_threat_ips = {
        e.get("source_ip", "") for e in threat_events if e.get("source_ip")
    }

    # Rule 1 — Brute force threshold
    bf_count = alert_types.count("Brute Force")
    if bf_count >= 2 or total_failed >= 40:
        alerts.append({
            "type": "Brute Force Campaign",
            "severity": "High",
            "description": (
                f"{bf_count} brute force events detected. "
                f"Total failed attempts: {total_failed}."
            ),
        })

    # Rule 2 — Multi-stage attack chain
    has_initial   = any(t in ("Brute Force", "Credential Stuffing", "Password Spray") for t in alert_types)
    has_exec      = any(t in ("Suspicious Activity", "Malware Execution") for t in alert_types)
    has_escalation = "Privilege Escalation" in alert_types
    has_cred_dump  = "Credential Dumping" in alert_types

    chain_stages = sum([has_initial, has_exec, has_escalation, has_cred_dump])

    if chain_stages >= 3:
        alerts.append({
            "type": "Full Attack Chain Detected",
            "severity": "Critical",
            "description": (
                f"Multi-stage attack across {chain_stages} MITRE stages. "
                f"Indicators: Initial Access → Execution → "
                + ("Priv Esc → " if has_escalation else "")
                + ("Cred Dump" if has_cred_dump else "Lateral Movement")
                + "."
            ),
        })
    elif chain_stages == 2:
        alerts.append({
            "type": "Partial Attack Chain",
            "severity": "High",
            "description": f"2-stage attack pattern detected across {len(threat_events)} events.",
        })

    # Rule 3 — Multiple threat IPs
    if len(unique_threat_ips) >= 3:
        alerts.append({
            "type": "Distributed Attack",
            "severity": "High",
            "description": (
                f"Threats observed from {len(unique_threat_ips)} distinct IPs. "
                "Possible coordinated attack."
            ),
        })

    # Rule 4 — Credential dumping
    if has_cred_dump:
        alerts.append({
            "type": "Credential Theft Attempt",
            "severity": "Critical",
            "description": "Credential dumping activity detected. Immediate response required.",
        })

    # Rule 5 — Privilege escalation
    if has_escalation and not has_cred_dump:
        alerts.append({
            "type": "Privilege Escalation",
            "severity": "High",
            "description": "Account or process privilege escalation observed.",
        })

    # Default
    if not alerts:
        if len(threat_events) > 0:
            alerts.append({
                "type": "Low-Level Suspicious Activity",
                "severity": "Medium",
                "description": f"{len(threat_events)} suspicious events detected. Monitor closely.",
            })
        else:
            alerts.append({
                "type": "No Threats Detected",
                "severity": "Low",
                "description": "All analyzed events appear benign.",
            })

    return alerts