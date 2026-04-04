def map_kill_chain(events):
    stages = []

    for e in events:
        alert = e.get("alert_type")

        if alert == "Brute Force":
            if "Initial Access" not in stages:
                stages.append("Initial Access")

        if alert in ["Suspicious Activity", "Malware Execution"]:
            if "Execution" not in stages:
                stages.append("Execution")

        if alert == "Credential Dumping":
            if "Credential Access" not in stages:
                stages.append("Credential Access")

        if alert == "Privilege Escalation":
            if "Privilege Escalation" not in stages:
                stages.append("Privilege Escalation")

    # 🔥 Add persistence if multiple stages
    if len(stages) >= 2:
        stages.append("Persistence")

    if len(stages) >= 3:
        stages.append("Lateral Movement")

    if len(stages) >= 4:
        stages.append("Full Attack Chain")

    return stages