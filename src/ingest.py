"""
ingest.py
═════════
Real-time log ingestion: watch folder + CSV tailing.

Sources:
  WatchFolder(path)
      Polls a directory for log files. Supports:
        - .csv  — tailed properly: new lines since last poll (byte offsets)
        - .evtx — new files parsed in full; existing files diffed by record
                  count (EVTX has no stable tail offset; documented approx.)
      poll() returns newly arrived parsed-log dicts (same schema as
      log_parser output). Never invents events.

  parse_csv_logs(path, skip_header=True)
      Parse a CSV in the parser/baseline schema:
      event_id, timestamp, alert_type, failed_logins, source_ip,
      location, device, process_risk
"""

import csv
import os
from datetime import datetime, timezone

from log_parser import parse_evtx


def _to_int(v, default=0):
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return default


def parse_csv_logs(path: str) -> list[dict]:
    """Parse a full CSV log file into parsed-log dicts."""
    logs = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("event_id"):
                continue
            logs.append({
                "event_id":      str(row.get("event_id", "")),
                "timestamp":     row.get("timestamp") or None,
                "alert_type":    row.get("alert_type", "Normal Login"),
                "failed_logins": _to_int(row.get("failed_logins")),
                "source_ip":     row.get("source_ip") or None,
                "location":      row.get("location", "Unknown"),
                "device":        row.get("device", "Unknown"),
                "process_risk":  1 if str(row.get("process_risk", "")).strip() == "1" else 0,
            })
    return logs


class WatchFolder:
    """
    Poll a folder for new log data.

    Usage:
        w = WatchFolder("watch/")
        while True:
            new_events = w.poll()   # [] when nothing arrived
            ...
            time.sleep(5)

    State (file offsets / seen EVTX record counts) lives in memory;
    use save_state()/load_state() to persist across restarts.
    """

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self._csv_offsets: dict[str, int] = {}   # path -> byte offset
        self._csv_headers: dict[str, list[str]] = {}  # path -> column names
        self._evtx_counts: dict[str, int] = {}   # path -> records parsed

    # ── State persistence ──────────────────────────────────────────────────

    def state(self) -> dict:
        return {"csv_offsets": dict(self._csv_offsets),
                "evtx_counts": dict(self._evtx_counts)}

    def restore(self, state: dict) -> None:
        self._csv_offsets = dict(state.get("csv_offsets", {}))
        self._evtx_counts = dict(state.get("evtx_counts", {}))

    # ── Polling ────────────────────────────────────────────────────────────

    def poll(self) -> list[dict]:
        """Return events that arrived since the last poll()."""
        new: list[dict] = []
        try:
            files = sorted(os.listdir(self.path))
        except OSError:
            return new

        for name in files:
            fpath = os.path.join(self.path, name)
            if not os.path.isfile(fpath):
                continue
            lower = name.lower()
            if lower.endswith(".csv"):
                new.extend(self._poll_csv(fpath))
            elif lower.endswith(".evtx"):
                new.extend(self._poll_evtx(fpath))
        return new

    def _poll_csv(self, fpath: str) -> list[dict]:
        offset = self._csv_offsets.get(fpath, 0)
        try:
            size = os.path.getsize(fpath)
        except OSError:
            return []
        if size < offset:
            offset = 0  # file was rotated/truncated — start over
        if size == offset:
            return []

        logs: list[dict] = []
        with open(fpath, "r", newline="", encoding="utf-8-sig") as f:
            if offset == 0:
                reader = csv.DictReader(f)
                cols = reader.fieldnames or []
                self._csv_headers[fpath] = cols
                rows = list(reader)
            else:
                cols = self._csv_headers.get(fpath)
                f.seek(offset)
                if not cols:
                    # Header unknown (fresh watcher on grown file): read it,
                    # then jump back to the offset.
                    pos = f.tell()
                    f.seek(0)
                    cols = next(csv.reader(f), [])
                    self._csv_headers[fpath] = cols
                    f.seek(pos)
                rows = [dict(zip(cols, r)) for r in csv.reader(f) if r]

        for row in rows:
            try:
                logs.append(self._row_to_log(row))
            except ValueError:
                continue  # blank / malformed row — skip, don't crash

        self._csv_offsets[fpath] = size
        return logs

    @staticmethod
    def _row_to_log(row: dict) -> dict:
        if not row.get("event_id"):
            raise ValueError("skip")
        return {
            "event_id":      str(row.get("event_id", "")),
            "timestamp":     row.get("timestamp") or None,
            "alert_type":    row.get("alert_type", "Normal Login"),
            "failed_logins": _to_int(row.get("failed_logins")),
            "source_ip":     row.get("source_ip") or None,
            "location":      row.get("location", "Unknown"),
            "device":        row.get("device", "Unknown"),
            "process_risk":  1 if str(row.get("process_risk", "")).strip() == "1" else 0,
        }

    def _poll_evtx(self, fpath: str) -> list[dict]:
        try:
            logs = parse_evtx(fpath)
        except Exception:
            return []
        seen = self._evtx_counts.get(fpath, 0)
        # EVTX has no stable tail offset: diff by record count. New records
        # are appended by the writer, so the tail slice is the new data.
        new = logs[seen:] if len(logs) > seen else []
        self._evtx_counts[fpath] = len(logs)
        return new


if __name__ == "__main__":
    import tempfile, time
    print("WatchFolder self-test\n" + "=" * 40)
    with tempfile.TemporaryDirectory() as tmp:
        w = WatchFolder(tmp)
        print("empty poll:", w.poll())
        with open(os.path.join(tmp, "a.csv"), "w", newline="") as f:
            f.write("event_id,timestamp,alert_type,failed_logins,source_ip,location,device,process_risk\n")
            f.write("4625,2026-01-06T10:00:00+00:00,Brute Force,3,45.33.32.1,Russia,Linux,0\n")
        got = w.poll()
        print("first poll:", len(got), got[0]["alert_type"] if got else None)
        print("second poll (no change):", w.poll())
        with open(os.path.join(tmp, "a.csv"), "a") as f:
            f.write("4624,2026-01-06T10:01:00+00:00,Normal Login,0,192.168.1.5,India,Windows,0\n")
        got = w.poll()
        print("third poll (appended):", len(got), got[0]["alert_type"] if got else None)
