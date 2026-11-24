import os
import sqlite3
from datetime import datetime, timezone
from auth import make_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "ledger.db")
SCHEMA_PATH = os.path.join(BASE, "schema.sql")

DEMO_USERS = [
    ("admin", "admin123", "Administrator", "Admin"),
    ("officer", "officer123", "Officer-001 (OFF-1021)", "Officer"),
    ("lab", "lab123", "Forensic Lab-001", "Laboratory"),
    ("custodian", "custodian123", "Custodian-001", "Custodian"),
    ("reviewer", "reviewer123", "Reviewer-001", "Reviewer"),
    ("officer1", "officer1-demo", "Officer-001", "Officer"),
]


def init_database(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    for username, pwd, full_name, role in DEMO_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, full_name, role, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, make_hash(pwd), full_name, role, stamp),
        )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_database()
    print("Database initialised successfully.")
