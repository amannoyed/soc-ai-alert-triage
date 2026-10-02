import xml.etree.ElementTree as ET

try:
    from Evtx.Evtx import Evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# Maps Sysmon/Security Event IDs to SOC alert categories.
# Values are CATEGORY labels only — severity lives in features.EVENT_RISK,
# and failed_logins below carries REAL per-event counts (a 4625 is one
# failed logon), never invented weights.
EVENT_ID_MAP = {
    "4625": "Brute Force",          # Failed logon
    "4624": "Normal Login",         # Successful logon
    "4648": "Suspicious Login",     # Logon with explicit credentials
    "4672": "Privilege Escalation", # Special privileges assigned
    "4688": "Suspicious Activity",  # Process created (Security log)
    "4698": "Suspicious Activity",  # Scheduled task created
    "4732": "Privilege Escalation", # Member added to security group
    "1":    "Suspicious Activity",  # Sysmon: Process Create
    "3":    "Suspicious Activity",  # Sysmon: Network Connection
    "7":    "Suspicious Activity",  # Sysmon: Image Loaded
    "10":   "Credential Dumping",   # Sysmon: Process Access (often lsass)
    "11":   "Suspicious Activity",  # Sysmon: File Created
}

MALICIOUS_PROCESSES = [
    "mimikatz", "psexec", "netcat", "nc.exe", "ncat", "pwdump",
    "fgdump", "gsecdump", "wce.exe", "procdump"
]

SUSPICIOUS_CMDLINE = [
    "-enc", "-encodedcommand", "iex(", "invoke-expression",
    "downloadstring", "webclient", "bypass", "-nop", "-noprofile",
    "hidden", "frombase64string"
]


def _extract_fields(root):
    event_id = None
    timestamp = None   # ISO-8601 SystemTime from the event XML; None if absent
    data_fields = {}

    for elem in root.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag == "EventID" and elem.text:
            event_id = elem.text.strip()
        elif tag == "TimeCreated":
            timestamp = elem.attrib.get("SystemTime")

    for data in root.iter():
        tag = data.tag.split("}")[-1] if "}" in data.tag else data.tag
        if tag == "Data" and data.attrib.get("Name"):
            data_fields[data.attrib["Name"]] = (data.text or "").strip()

    return event_id, timestamp, data_fields


def _classify_event(event_id, data_fields):
    alert_type = "Normal Login"
    failed_logins = 0
    source_ip = None   # None when the event carries no usable IP — never invent one
    process_risk = 0   # 1 when a known-malicious process / suspicious cmdline is seen

    base = EVENT_ID_MAP.get(event_id, "Normal Login")
    alert_type = base
    # Honest per-event count: one 4625 record = one failed logon.
    # (Aggregation across windows happens in the correlation engine.)
    failed_logins = 1 if event_id == "4625" else 0

    # Extract real IP if present
    for ip_field in ("IpAddress", "SourceAddress", "Workstation"):
        ip = data_fields.get(ip_field, "")
        if ip and ip not in ("-", "", "::1", "127.0.0.1"):
            source_ip = ip
            break

    # Sysmon process analysis
    if event_id in ("1", "4688"):
        process = data_fields.get("Image", "").lower()
        cmd = data_fields.get("CommandLine", "").lower()

        for bad in MALICIOUS_PROCESSES:
            if bad in process:
                alert_type = "Credential Dumping"
                process_risk = 1
                break

        if alert_type != "Credential Dumping":
            if "powershell" in process:
                alert_type = "Suspicious Activity"
                for sus in SUSPICIOUS_CMDLINE:
                    if sus in cmd:
                        alert_type = "Malware Execution"
                        process_risk = 1
                        break
            elif "cmd.exe" in process:
                alert_type = "Suspicious Activity"

    # Sysmon process access → lsass dump
    if event_id == "10":
        target = data_fields.get("TargetImage", "").lower()
        if "lsass" in target:
            alert_type = "Credential Dumping"
            process_risk = 1

    return alert_type, failed_logins, source_ip, process_risk


def parse_evtx(file_path: str) -> list[dict]:
    """
    Parse a Windows .evtx file into a list of event dicts.

    Each dict: {event_id, timestamp (ISO-8601 SystemTime or None),
                alert_type, failed_logins, source_ip (or None)}.

    Returns [] when the file yields no usable events.
    NEVER fabricates events — callers must handle the empty case explicitly.
    """
    if not EVTX_AVAILABLE:
        raise RuntimeError(
            "python-evtx is not installed; cannot parse .evtx files. "
            "Install it with: pip install python-evtx"
        )

    logs = []
    with Evtx(file_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                event_id, timestamp, data_fields = _extract_fields(root)

                if event_id is None:
                    continue

                alert_type, failed_logins, source_ip, process_risk = _classify_event(
                    event_id, data_fields
                )

                logs.append({
                    "event_id":      event_id,
                    "timestamp":     timestamp,
                    "alert_type":    alert_type,
                    "failed_logins": failed_logins,
                    "source_ip":     source_ip,
                    "process_risk":  process_risk,
                })

            except ET.ParseError:
                continue

    return logs