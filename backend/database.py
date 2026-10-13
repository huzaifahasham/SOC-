
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "cybersentinel.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            computer_name TEXT NOT NULL,
            channel TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            source_ip TEXT,
            username TEXT,
            timestamp TEXT NOT NULL,
            details TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            computer_name TEXT NOT NULL,
            source_ip TEXT,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            evidence TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incident_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            note TEXT DEFAULT '',
            changed_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        );
        """)


def save_event(event):
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO events
            (event_key, computer_name, channel, event_id,
             source_ip, username, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["event_key"],
            event["computer_name"],
            event["channel"],
            event["event_id"],
            event.get("source_ip"),
            event.get("username"),
            event["timestamp"],
            json.dumps(event.get("details", {}), ensure_ascii=False),
        ))
        return cursor.rowcount == 1


def count_recent_failures(computer_name, source_ip, minutes=5):
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=minutes)
    ).isoformat()

    with get_connection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS total
            FROM events
            WHERE event_id = 4625
              AND computer_name = ?
              AND source_ip = ?
              AND timestamp >= ?
        """, (computer_name, source_ip, cutoff)).fetchone()

    return row["total"]


def create_incident(event, count, threshold=12):
    now = datetime.now(timezone.utc).isoformat()
    source_ip = event.get("source_ip")

    if count < threshold or not source_ip:
        return None

    with get_connection() as conn:
        existing = conn.execute("""
            SELECT id FROM incidents
            WHERE computer_name = ?
              AND source_ip = ?
              AND title = ?
              AND status != 'Resolved'
              AND created_at >= ?
            LIMIT 1
        """, (
            event["computer_name"],
            source_ip,
            "Repeated Failed Login Attempts",
            (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        )).fetchone()

        if existing:
            return existing["id"]

        cursor = conn.execute("""
            INSERT INTO incidents
            (title, computer_name, source_ip, severity, risk_score,
             evidence, recommended_action, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?, ?)
        """, (
            "Repeated Failed Login Attempts",
            event["computer_name"],
            source_ip,
            "High",
            85,
            json.dumps({
                "failed_attempts": count,
                "window_minutes": 5,
                "trigger_event_id": event["event_id"],
                "last_event_timestamp": event["timestamp"],
            }),
            "Verify the source IP and related authentication events. "
            "If the activity is unauthorized, follow your incident "
            "response procedure to protect the account.",
            now,
            now,
        ))

        incident_id = cursor.lastrowid
        conn.execute("""
            INSERT INTO incident_history
            (incident_id, old_status, new_status, note, changed_at)
            VALUES (?, NULL, 'New', 'Incident created automatically', ?)
        """, (incident_id, now))

        return incident_id


def list_incidents():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT * FROM incidents ORDER BY created_at DESC
        """).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        results.append(item)
    return results


def update_incident_status(incident_id, new_status, note=""):
    allowed = {"New", "Investigating", "Resolved"}
    if new_status not in allowed:
        raise ValueError("Invalid incident status")

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        old = conn.execute(
            "SELECT status FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if old is None:
            return False

        conn.execute("""
            UPDATE incidents SET status = ?, updated_at = ?
            WHERE id = ?
        """, (new_status, now, incident_id))

        conn.execute("""
            INSERT INTO incident_history
            (incident_id, old_status, new_status, note, changed_at)
            VALUES (?, ?, ?, ?, ?)
        """, (incident_id, old["status"], new_status, note, now))

    return True
