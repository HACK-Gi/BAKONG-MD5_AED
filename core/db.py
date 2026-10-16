import os
import sqlite3
from contextlib import contextmanager
from core.config import Config

# ensure data dir exists
_db_dir = os.path.dirname(Config.DB_PATH) or "."
os.makedirs(_db_dir, exist_ok=True)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    email            TEXT UNIQUE NOT NULL,
    password_hash    TEXT,
    created_at       INTEGER NOT NULL,
    google_id        TEXT,
    email_verified   INTEGER NOT NULL DEFAULT 0,
    avatar_url       TEXT,
    display_name     TEXT,
    verify_last_sent INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subscriptions (
    user_id          INTEGER PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'pending',
    expires_at       INTEGER,
    last_payment_md5 TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    md5          TEXT UNIQUE,
    amount       REAL NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   INTEGER NOT NULL,
    plan         TEXT,
    qr_md5       TEXT,
    qr_string    TEXT,
    bill_number  TEXT,
    expires_at   INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    key_hash   TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    name       TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS usage_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id     INTEGER NOT NULL,
    md5        TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_verify (
    user_id     INTEGER NOT NULL,
    token_hash  TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_attempts (
    email        TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL DEFAULT 0,
    first_at     INTEGER NOT NULL,
    locked_until INTEGER
);

CREATE TABLE IF NOT EXISTS login_otp (
    email       TEXT PRIMARY KEY,
    otp_hash    TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_sent   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
    bucket   TEXT NOT NULL,
    ts       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_hash     ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_keys_user     ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_key     ON usage_log(key_id, created_at);
CREATE INDEX IF NOT EXISTS idx_verify_user   ON email_verify(user_id);
CREATE INDEX IF NOT EXISTS idx_rate_bucket   ON rate_limits(bucket, ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id
    ON users(google_id) WHERE google_id IS NOT NULL;
"""

# auto-migrate: add columns that might be missing on legacy DBs
MIGRATIONS = {
    "users": [
        ("google_id",        "TEXT"),
        ("email_verified",   "INTEGER NOT NULL DEFAULT 0"),
        ("avatar_url",       "TEXT"),
        ("display_name",     "TEXT"),
        ("verify_last_sent", "INTEGER"),
    ],
    "payments": [
        ("plan",        "TEXT"),
        ("qr_md5",      "TEXT"),
        ("qr_string",   "TEXT"),
        ("bill_number", "TEXT"),
        ("expires_at",  "INTEGER"),
    ],
}


def _migrate(conn):
    for table, cols in MIGRATIONS.items():
        existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for col, typ in cols:
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")


def init_db():
    with connect() as c:
        c.executescript(SCHEMA)
        _migrate(c)
        c.commit()


@contextmanager
def connect():
    conn = sqlite3.connect(Config.DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def query(sql, args=(), one=False):
    with connect() as c:
        cur = c.execute(sql, args)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    with connect() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid
