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

                # ---------------- 🔥 IMPROVED SYSMON DETECTION ---------------- #

                if event_id == "1":  # Sysmon Process Creation
                    process = data_fields.get("Image", "").lower()
                    cmd = data_fields.get("CommandLine", "").lower()

                    # 🔥 HIGH RISK (real attack tools)
                    if any(x in process for x in ["mimikatz", "psexec", "netcat"]):
                        log_entry["alert_type"] = "Credential Dumping"
                        log_entry["failed_logins"] = 25

                    # 🔥 MALWARE / SCRIPT EXECUTION
                    elif "powershell" in process:
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 15

                        if any(x in cmd for x in ["-enc", "iex", "download"]):
                            log_entry["alert_type"] = "Malware Execution"
                            log_entry["failed_logins"] = 22

                    # 🔥 COMMAND EXECUTION
                    elif "cmd.exe" in process:
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 10

                    # 🔥 DEFAULT: ANY process = mild signal
                    else:
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 5

                logs.append(log_entry)

    except Exception as e:
        print("Error parsing EVTX:", e)

    return logs