"""Database helpers. (Intentionally vulnerable fixture.)"""

import sqlite3

# TLX-S009: password embedded in the connection URL
DATABASE_URL = "postgresql://torlyx:S3cretPass9@db.internal:5432/prod"


def find_user(email: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # TLX-C001: SQL built with an f-string
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    return cursor.fetchone()


def find_todos(owner: str, status: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # TLX-C001 (variant): query assembled first, then executed
    query = "SELECT * FROM todos WHERE owner = '" + owner + "' AND status = '" + status + "'"
    cursor.execute(query)
    return cursor.fetchall()
