from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

def parse_evtx(file_path):
    logs = []

    try:
        with Evtx(file_path) as log:
            for record in log.records():

                xml_data = record.xml()
                root = ET.fromstring(xml_data)

                event_id = None
                data_fields = {}

                # Extract Event ID
                for elem in root.iter():
                    if "EventID" in elem.tag:
                        event_id = elem.text

                # Extract event data fields
                for data in root.iter():
                    if "Data" in data.tag and data.attrib.get("Name"):
                        data_fields[data.attrib["Name"]] = data.text

                # Default log structure
                log_entry = {
                    "failed_logins": 0,
                    "alert_type": "Normal Login",
                    "source_ip": "8.8.8.8"
                }

                # ---------------- 🔥 DETECTION RULES ---------------- #

                # ❌ Failed Login → Brute Force
                if event_id == "4625":
                    log_entry["failed_logins"] = 15
                    log_entry["alert_type"] = "Brute Force"

                    ip = data_fields.get("IpAddress")
                    if ip and ip != "-":
                        log_entry["source_ip"] = ip

                # ✅ Successful Login
                elif event_id == "4624":
                    log_entry["alert_type"] = "Normal Login"

                    ip = data_fields.get("IpAddress")
                    if ip and ip != "-":
                        log_entry["source_ip"] = ip

                # 🔥 Privilege Escalation
                elif event_id == "4672":
                    log_entry["alert_type"] = "Privilege Escalation"
                    log_entry["failed_logins"] = 10

                # ⚠️ Suspicious Process (Sysmon)
                elif event_id == "1":
                    process = data_fields.get("Image", "").lower()

                    if any(x in process for x in ["powershell", "cmd.exe", "mimikatz"]):
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 8

                logs.append(log_entry)

    except Exception as e:
        print("Error parsing EVTX:", e)

    return logs