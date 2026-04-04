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

                for elem in root.iter():
                    if "EventID" in elem.tag:
                        event_id = elem.text

                for data in root.iter():
                    if "Data" in data.tag and data.attrib.get("Name"):
                        data_fields[data.attrib["Name"]] = data.text

                log_entry = {
                    "failed_logins": 0,
                    "alert_type": "Normal Login",
                    "source_ip": "8.8.8.8"
                }

        # 🔥 FORCE TEST (for demo)

log_entry["alert_type"] = "Malware Execution"
log_entry["failed_logins"] = 25

                # ---------------- 🔥 SYSMON DETECTION ---------------- #

                if event_id == "1":  # Sysmon Process Creation
                    process = data_fields.get("Image", "").lower()
                    cmd = data_fields.get("CommandLine", "").lower()

                    # 🔥 MALICIOUS TOOL DETECTION
                    if any(x in process for x in ["mimikatz", "psexec", "netcat"]):
                        log_entry["alert_type"] = "Credential Dumping"
                        log_entry["failed_logins"] = 20

                    # 🔥 POWERSHELL ABUSE
                    elif "powershell" in process:
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 10

                        if any(x in cmd for x in ["-enc", "download", "iex"]):
                            log_entry["alert_type"] = "Malware Execution"
                            log_entry["failed_logins"] = 18

                    # 🔥 CMD EXECUTION
                    elif "cmd.exe" in process:
                        log_entry["alert_type"] = "Suspicious Activity"
                        log_entry["failed_logins"] = 6

                logs.append(log_entry)

    except Exception as e:
        print("Error parsing EVTX:", e)

    return logs