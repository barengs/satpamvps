"""
Database manager for VPS Sentinel - SQLite persistence layer
"""
import sqlite3
import os
from datetime import datetime
from config import DATABASE_PATH


def get_connection():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database schema"""
    conn = get_connection()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            country     TEXT    DEFAULT 'Unknown',
            attack_type TEXT    NOT NULL,
            attack_name TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            details     TEXT,
            action      TEXT    DEFAULT 'DETECTED',
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    UNIQUE NOT NULL,
            reason      TEXT,
            blocked_at  TEXT    DEFAULT (datetime('now')),
            unblock_at  TEXT,
            is_active   INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS system_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            cpu_percent REAL,
            ram_percent REAL,
            net_bytes_sent INTEGER,
            net_bytes_recv INTEGER,
            active_connections INTEGER
        );
    """)
    conn.commit()
    conn.close()


def insert_event(ip, country, attack_type, attack_name, severity, details="", action="DETECTED"):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO events (timestamp, ip, country, attack_type, attack_name, severity, details, action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, country, attack_type, attack_name, severity, details, action))
    conn.commit()
    event_id = c.lastrowid
    conn.close()
    return event_id


def block_ip(ip, reason="", duration_seconds=0):
    conn = get_connection()
    c = conn.cursor()
    unblock_at = None
    if duration_seconds > 0:
        from datetime import timedelta
        unblock_at = (datetime.now() + timedelta(seconds=duration_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO blocked_ips (ip, reason, unblock_at, is_active)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET is_active=1, reason=excluded.reason, blocked_at=datetime('now'), unblock_at=excluded.unblock_at
    """, (ip, reason, unblock_at))
    conn.commit()
    conn.close()


def unblock_ip(ip):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE blocked_ips SET is_active=0 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()


def is_ip_blocked(ip):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM blocked_ips WHERE ip=? AND is_active=1", (ip,))
    result = c.fetchone()
    conn.close()
    return result is not None


def get_blocked_ips():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT ip, reason, blocked_at, unblock_at FROM blocked_ips WHERE is_active=1 ORDER BY blocked_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_recent_events(limit=100):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, timestamp, ip, country, attack_type, attack_name, severity, details, action
        FROM events ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_stats_summary():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as total FROM events")
    total = c.fetchone()["total"]
    c.execute("SELECT COUNT(*) as total FROM blocked_ips WHERE is_active=1")
    blocked = c.fetchone()["total"]
    c.execute("SELECT COUNT(*) as total FROM events WHERE severity='CRITICAL'")
    critical = c.fetchone()["total"]
    c.execute("SELECT attack_type, COUNT(*) as cnt FROM events GROUP BY attack_type ORDER BY cnt DESC LIMIT 5")
    top_attacks = [dict(r) for r in c.fetchall()]
    conn.close()
    return {
        "total_events": total,
        "blocked_ips": blocked,
        "critical_events": critical,
        "top_attacks": top_attacks,
    }


def insert_system_stat(cpu, ram, bytes_sent, bytes_recv, connections):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO system_stats (timestamp, cpu_percent, ram_percent, net_bytes_sent, net_bytes_recv, active_connections)
        VALUES (datetime('now'), ?, ?, ?, ?, ?)
    """, (cpu, ram, bytes_sent, bytes_recv, connections))
    conn.commit()
    conn.close()
