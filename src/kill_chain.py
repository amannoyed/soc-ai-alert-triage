def map_kill_chain(events):
    stages = []

    for e in events:
        alert = e.get("alert_type")

        if alert == "Brute Force":
            if "Initial Access" not in stages:
                stages.append("Initial Access")

        elif alert in ["Malware Execution", "Suspicious Activity"]:
            if "Execution" not in stages:
                stages.append("Execution")

        elif alert == "Privilege Escalation":
            if "Privilege Escalation" not in stages:
                stages.append("Privilege Escalation")

        elif alert == "Credential Dumping":
            if "Credential Access" not in stages:
                stages.append("Credential Access")

    # 🔥 Persistence logic (multi-stage)
    if len(stages) >= 3:
        stages.append("Persistence")

    # 🔥 If full attack chain
    if len(stages) >= 4:
        stages.append("Full Attack Chain Detected")

    return stages