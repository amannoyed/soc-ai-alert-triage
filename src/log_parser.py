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

                # Extract event data
                for data in root.iter():
                    if "Data" in data.tag and data.attrib.get("Name"):
                        data_fields[data.attrib["Name"]] = data.text

                log_entry = {
                    "failed_logins": 0,
                    "alert_type": "Normal Login",
                    "source_ip": "8.8.8.8"
                }

                # ---------------- 🔥 DETECTION RULES ---------------- #

                # ❌ Failed Login (Brute Force Indicator)
                if event_id == "4625":
                    log_entry["failed_logins"] = 5
                    log_entry["alert_type"] = "Brute Force"

                    if "IpAddress" in data_fields:
                        log_entry["source_ip"] = data_fields["IpAddress"]

                # ✅ Successful Login
                elif event_id == "4624":
                    log_entry["alert_type"] = "Normal Login"

                    if "IpAddress" in data_fields:
                        log_entry["source_ip"] = data_fields["IpAddress"]

                # ⚠️ Suspicious Process (Sysmon Event ID 1)
                elif event_id == "1":
                    process = data_fields.get("Image", "").lower()

                    if any(x in process for x in ["cmd.exe", "powershell", "mimikatz"]):
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 2

                logs.append(log_entry)

    except Exception as e:
        print("Error parsing EVTX:", e)

    return logs