"""
Initialise the vuln_lab SQLite database.

============================== AUTHORIZED USE ONLY =============================
This script creates a SQLite database file (lab.db) populated with deliberately
weak credentials (plaintext passwords; default admin/admin account). The lab
runs on your own loopback only.
================================================================================

The schema:

    users
        id          INTEGER PRIMARY KEY
        username    TEXT UNIQUE NOT NULL
        password    TEXT NOT NULL          -- plaintext! (CWE-256; patched in Lecture 3)
        email       TEXT
        role        TEXT NOT NULL          -- 'user' or 'admin'

    invoices
        id          INTEGER PRIMARY KEY
        owner_id    INTEGER NOT NULL
        amount      INTEGER NOT NULL       -- cents
        description TEXT

    comments
        id          INTEGER PRIMARY KEY
        body        TEXT

The seed data:

    alice / password123       (role: user)
    bob   / letmein           (role: user)
    admin / admin             (role: admin)

Plus two invoices per user and zero comments.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


DB_PATH: Path = Path(__file__).parent / "lab.db"


SCHEMA: str = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    description TEXT,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    body TEXT
);
"""


SEED_USERS: list[tuple[str, str, str, str]] = [
    ("alice", "password123", "alice@lab.local", "user"),
    ("bob", "letmein", "bob@lab.local", "user"),
    ("admin", "admin", "admin@lab.local", "admin"),
]


SEED_INVOICES: list[tuple[int, int, str]] = [
    # (owner_id, amount_cents, description)
    (1, 1200, "Coffee subscription, March"),
    (1, 4500, "Domain renewal"),
    (2, 7500, "Cloud bill, March"),
    (2, 1899, "Streaming, March"),
    (3, 0, "Admin housekeeping"),
    (3, 0, "Admin housekeeping (2)"),
]


def create_schema(conn: sqlite3.Connection) -> None:
    """Create the lab tables if they do not already exist."""
    conn.executescript(SCHEMA)


def seed_users(conn: sqlite3.Connection) -> int:
    """Insert the seed users. Returns the number of rows inserted."""
    cursor = conn.cursor()
    inserted: int = 0
    for username, password, email, role in SEED_USERS:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, role) "
            "VALUES (?, ?, ?, ?)",
            (username, password, email, role),
        )
        inserted += cursor.rowcount
    conn.commit()
    return inserted


def seed_invoices(conn: sqlite3.Connection) -> int:
    """Insert the seed invoices. Returns the number of rows inserted."""
    cursor = conn.cursor()
    inserted: int = 0
    for owner_id, amount, description in SEED_INVOICES:
        cursor.execute(
            "INSERT INTO invoices (owner_id, amount, description) "
            "VALUES (?, ?, ?)",
            (owner_id, amount, description),
        )
        inserted += cursor.rowcount
    conn.commit()
    return inserted


def main() -> int:
    """Create the schema, seed users and invoices, and report the counts."""
    if DB_PATH.exists():
        print(
            f"NOTE: {DB_PATH} already exists. Re-running init_db will not "
            "overwrite existing rows; delete the file first for a clean run.",
            file=sys.stderr,
        )
    conn = sqlite3.connect(str(DB_PATH))
    try:
        create_schema(conn)
        u_count: int = seed_users(conn)
        i_count: int = seed_invoices(conn)
    finally:
        conn.close()
    print(f"lab.db created with {u_count} users and {i_count} invoices.")
    print("Seed credentials (plaintext; this is a deliberate finding):")
    for username, password, _, role in SEED_USERS:
        print(f"  {username:<10} / {password:<15}  (role: {role})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
