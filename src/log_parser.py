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

if event_id == "4625":  # Failed login
    log_entry["failed_logins"] = 15   # 🔥 increase weight
    log_entry["alert_type"] = "Brute Force"

    ip = data_fields.get("IpAddress")
    if ip and ip != "-":
        log_entry["source_ip"] = ip


elif event_id == "4624":  # Success login
    log_entry["alert_type"] = "Normal Login"

    ip = data_fields.get("IpAddress")
    if ip and ip != "-":
        log_entry["source_ip"] = ip


elif event_id == "4672":  # 🔥 Admin privilege assigned
    log_entry["alert_type"] = "Privilege Escalation"
    log_entry["failed_logins"] = 10


elif event_id == "1":  # Sysmon process
    process = data_fields.get("Image", "").lower()

    if any(x in process for x in ["powershell", "cmd.exe", "mimikatz"]):
        log_entry["alert_type"] = "Suspicious Activity"
        log_entry["failed_logins"] = 8