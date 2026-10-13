"""SQLite request log shared by the proxy (writer) and dashboard (reader)."""
import os
import sqlite3
import time

DB_PATH = os.environ.get("PROXY_DB", "proxy_log.db")
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    client TEXT,
    method TEXT,
    host TEXT,
    action TEXT,
    category TEXT,
    reason TEXT,
    bytes INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_action ON requests(action);
"""


def connect(path=None):
    conn = sqlite3.connect(path or DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    global _conn
    _conn = connect()
    _conn.executescript(SCHEMA)
    _conn.commit()


def log_request(client, method, host, action, category, reason, nbytes=0):
    if _conn is None:
        init_db()
    with _conn:
        _conn.execute(
            "INSERT INTO requests (ts, client, method, host, action, category, reason, bytes) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), client, method, host, action, category, reason, nbytes),
        )
