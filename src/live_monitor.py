import time
from log_parser import parse_evtx

LOG_FILE = "logs/UACME_59_Sysmon.evtx"

def stream_logs():
    last_count = 0

    while True:
        logs = parse_evtx(LOG_FILE)

        # Only return NEW logs
        new_logs = logs[last_count:]

        last_count = len(logs)

        yield new_logs

        time.sleep(5)