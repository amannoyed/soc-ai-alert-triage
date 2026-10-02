"""
triage_store.py
═══════════════
Persistent SOC alert queue (SQLite).

Alerts are DEDUPLICATED: repeats of the same (source_ip, event_id,
alert_type) within a dedup window increment a counter instead of creating
new rows. This is what makes it a triage queue rather than an event list.

Analyst workflow states:
  open → investigating → closed_true_positive | closed_false_positive
  any → suppressed (temporarily muted)

The closed_* states are honest analyst labels. feedback_model.py trains a
RandomForest on them — the only supervised model in the project, and the
only one trained on real labels (analyst decisions, not synthetic data).

DB lives at <repo>/model/triage.db (relative path — works on Streamlit
Cloud; note data is ephemeral there unless you attach storage).
"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone, timedelta

_BASE     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DB_PATH  = os.path.join(_BASE, "model", "triage.db")

DEDUP_WINDOW_MINUTES = 60

STATUSES = ("open", "investigating", "closed_true_positive",
            "closed_false_positive", "suppressed")

_SEV_TO_RISK = {"Critical": 90, "High": 70, "Medium": 45, "Low": 20}


def _plain_severity(sev: str) -> str:
    """'🟠 High' → 'High'; already-plain values pass through."""
    for plain in ("Critical", "High", "Medium", "Low"):
        if plain in str(sev):
            return plain
    return "Low"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key    TEXT UNIQUE NOT NULL,
    source_ip     TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    alert_type    TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    severity      TEXT NOT NULL,
    mitre         TEXT NOT NULL DEFAULT '[]',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    event_count   INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'open',
    analyst       TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    status_updated_at TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_score  ON alerts(risk_score DESC);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dedupe_key(source_ip: str, event_id: str, alert_type: str,
                ts: str | None) -> str:
    """Same entity+type within the dedup window → same alert."""
    try:
        dt = datetime.fromisoformat(str(ts)) if ts else datetime.now(timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    bucket = dt.replace(minute=dt.minute // DEDUP_WINDOW_MINUTES * DEDUP_WINDOW_MINUTES,
                        second=0, microsecond=0).isoformat()
    raw = f"{source_ip}|{event_id}|{alert_type}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class TriageStore:
    """Thread-safe SQLite alert queue."""

    def __init__(self, path: str = _DB_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()
        with self._lock, sqlite3.connect(path) as c:
            c.executescript(SCHEMA)

    # ── Ingest ─────────────────────────────────────────────────────────────

    def _connect(self):
        c = sqlite3.connect(self.path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def upsert_alert(self, source_ip: str, event_id: str, alert_type: str,
                     risk_score: int, severity: str,
                     mitre: list | None = None,
                     timestamp: str | None = None) -> int:
        """
        Insert or bump an alert. Returns the alert id.
        Only alerts worth triaging should be ingested (caller filters by
        score threshold).
        """
        key = _dedupe_key(source_ip or "unknown", event_id, alert_type,
                          timestamp)
        now = _now_iso()
        mitre_json = json.dumps(mitre or [])
        with self._lock, self._connect() as c:
            cur = c.execute("SELECT id, event_count, risk_score FROM alerts "
                            "WHERE dedupe_key = ?", (key,))
            row = cur.fetchone()
            if row:
                new_count = row["event_count"] + 1
                new_score = max(row["risk_score"], risk_score)
                c.execute("UPDATE alerts SET event_count = ?, risk_score = ?, "
                          "last_seen = ? WHERE id = ?",
                          (new_count, new_score, now, row["id"]))
                return row["id"]
            cur = c.execute(
                "INSERT INTO alerts (dedupe_key, source_ip, event_id, "
                "alert_type, risk_score, severity, mitre, first_seen, "
                "last_seen, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, source_ip or "unknown", event_id, alert_type,
                 risk_score, severity, mitre_json, now, now, now))
            return cur.lastrowid

    def ingest_detection(self, log: dict, risk_score: int, severity: str,
                         mitre: list | None = None,
                         min_score: int = 30) -> int | None:
        """Convenience: ingest one scored log dict. Returns id or None."""
        if risk_score < min_score:
            return None
        return self.upsert_alert(
            source_ip=log.get("source_ip") or "unknown",
            event_id=str(log.get("event_id", "?")),
            alert_type=log.get("alert_type", "Unknown"),
            risk_score=risk_score, severity=_plain_severity(severity),
            mitre=mitre, timestamp=log.get("timestamp"))

    def ingest_correlation(self, alert) -> list[int]:
        """
        Ingest a CorrelatedAlert (burst / chain / slow-bf / distributed) as
        first-class queue entries — one per attributed source IP. These are
        the detections that matter; raw events are context.
        """
        ids = []
        risk = max(_SEV_TO_RISK.get(alert.severity, 20),
                   int(getattr(alert, "confidence", 0)))
        for ip in getattr(alert, "source_ips", []):
            ids.append(self.upsert_alert(
                source_ip=ip,
                event_id=f"CORR-{getattr(alert, 'attack_type', 'alert')}",
                alert_type=alert.name,
                risk_score=risk,
                severity=_plain_severity(alert.severity),
                mitre=list(getattr(alert, "mitre_techniques", [])),
                timestamp=getattr(alert, "last_event_ts", None)))
        return ids

    # ── Triage workflow ────────────────────────────────────────────────────

    def set_status(self, alert_id: int, status: str, analyst: str = "",
                   notes: str = "") -> bool:
        if status not in STATUSES:
            raise ValueError(f"Unknown status {status!r}. Choose from {STATUSES}")
        with self._lock, self._connect() as c:
            cur = c.execute(
                "UPDATE alerts SET status = ?, analyst = ?, notes = ?, "
                "status_updated_at = ? WHERE id = ?",
                (status, analyst, notes, _now_iso(), alert_id))
            return cur.rowcount > 0

    def get(self, alert_id: int) -> dict | None:
        with self._lock, self._connect() as c:
            row = c.execute("SELECT * FROM alerts WHERE id = ?",
                            (alert_id,)).fetchone()
            return dict(row) if row else None

    def list_alerts(self, status: str | None = None,
                    min_score: int = 0, limit: int = 200) -> list[dict]:
        q = "SELECT * FROM alerts WHERE risk_score >= ?"
        params: list = [min_score]
        if status:
            q += " AND status = ?"
            params.append(status)
        q += " ORDER BY risk_score DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as c:
            return [dict(r) for r in c.execute(q, params).fetchall()]

    # ── Stats (drive the dashboard KPIs from real data) ────────────────────

    def stats(self) -> dict:
        with self._lock, self._connect() as c:
            total = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
            by_status = {r["status"]: r["n"] for r in c.execute(
                "SELECT status, COUNT(*) n FROM alerts GROUP BY status")}
            by_sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
            open_critical = c.execute(
                "SELECT COUNT(*) n FROM alerts WHERE status IN "
                "('open','investigating') AND risk_score >= 80").fetchone()["n"]
        return {"total": total, "by_status": by_status,
                "by_severity": by_sev, "open_critical": open_critical}

    # ── Analyst labels for the feedback model ──────────────────────────────

    def labeled_events(self) -> list[tuple[dict, int]]:
        """
        Return (feature_log, label) pairs from analyst decisions.
        closed_true_positive → 1, closed_false_positive → 0.
        The feature_log is a minimal honest log dict (no alert_type leakage
        into features — features.py never uses it anyway).
        """
        with self._lock, self._connect() as c:
            rows = c.execute(
                "SELECT source_ip, event_id, alert_type, status FROM alerts "
                "WHERE status IN ('closed_true_positive','closed_false_positive')"
            ).fetchall()
        out = []
        for r in rows:
            label = 1 if r["status"] == "closed_true_positive" else 0
            out.append(({"source_ip": r["source_ip"],
                         "event_id": r["event_id"],
                         # NOTE: alert_type intentionally NOT passed —
                         # features must not see it.
                         "failed_logins": 0,
                         "timestamp": None}, label))
        return out


if __name__ == "__main__":
    import tempfile
    print("TriageStore self-test\n" + "=" * 40)
    with tempfile.TemporaryDirectory() as tmp:
        s = TriageStore(os.path.join(tmp, "t.db"))
        a1 = s.upsert_alert("45.33.32.1", "4625", "Brute Force", 70, "🟠 High")
        a2 = s.upsert_alert("45.33.32.1", "4625", "Brute Force", 75, "🟠 High")
        print("dedupe:", a1 == a2, "(same id → bumped)")
        s.set_status(a1, "investigating", analyst="Aman", notes="looking")
        s.set_status(a1, "closed_true_positive", analyst="Aman")
        print("stats:", s.stats())
        print("labels:", s.labeled_events())
        print("queue:", [(a["id"], a["status"], a["event_count"])
                         for a in s.list_alerts()])
