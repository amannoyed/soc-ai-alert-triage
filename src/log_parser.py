from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import random

def parse_evtx(file_path):
    events = []

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = ET.fromstring(xml)

                event_data = {
                    "failed_logins": 0,
                    "alert_type": "Normal Login",

                    # 🔥 ADD DEFAULT FEATURES FOR MODEL
                    "location_India": 0,
                    "location_US": 0,
                    "location_Russia": 0,
                    "location_China": 0,
                    "location_North Korea": 0,

                    "device_Windows": 1,
                    "device_Linux": 0,
                    "device_Android": 0,
                    "device_iOS": 0,
                }

                # 🔥 RANDOMIZE LOCATION (simulation)
                rand_loc = random.choice(["India","US","Russia","China"])
                event_data[f"location_{rand_loc}"] = 1

                event_id = root.find(".//EventID")

                if event_id is not None:
                    event_id = event_id.text

                    if event_id == "4625":
                        event_data["failed_logins"] += 1
                        event_data["alert_type"] = "Brute Force"

                    elif event_id == "4624":
                        event_data["alert_type"] = "Normal Login"

                    elif event_id == "1":
                        event_data["alert_type"] = "Suspicious Activity"

                events.append(event_data)

            except:
                continue

    return events