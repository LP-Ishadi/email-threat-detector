import sqlite3

DB_NAME = "scans.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_text TEXT,
            filename TEXT,
            total_score INTEGER,
            verdict TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_scan(email_text, filename, total_score, verdict):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (email_text, filename, total_score, verdict)
        VALUES (?, ?, ?, ?)
    """, (email_text, filename, total_score, verdict))

    conn.commit()
    conn.close()


def get_recent_scans(limit=5):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, email_text, filename, total_score, verdict, scanned_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return rows