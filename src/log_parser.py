from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

def parse_evtx(file_path):
    logs = []

    try:
        with Evtx(file_path) as log:
            for i, record in enumerate(log.records()):

                xml_data = record.xml()
                root = ET.fromstring(xml_data)

                log_entry = {
                    "failed_logins": 0,
                    "alert_type": "Normal Login",
                    "source_ip": "8.8.8.8"
                }

                # 🔥 FORCE MULTI-STAGE ATTACK SIMULATION

                if i == 0:
                    log_entry["alert_type"] = "Brute Force"
                    log_entry["failed_logins"] = 20

                elif i == 1:
                    log_entry["alert_type"] = "Brute Force"
                    log_entry["failed_logins"] = 25

                elif i == 2:
                    log_entry["alert_type"] = "Malware Execution"
                    log_entry["failed_logins"] = 30

                elif i == 3:
                    log_entry["alert_type"] = "Privilege Escalation"
                    log_entry["failed_logins"] = 35

                elif i >= 4:
                    log_entry["alert_type"] = "Credential Dumping"
                    log_entry["failed_logins"] = 40

                logs.append(log_entry)

    except Exception as e:
        print("Error parsing EVTX:", e)

    return logs