"""
SQLite database — schema, connection management, and query helpers.

Design decisions:
  - No ORM. The schema is simple enough that raw SQL is cleaner and more portable.
  - asyncio.to_thread() wraps all DB calls so the FastAPI event loop isn't blocked.
  - sqlite3.Row means rows are accessible as dicts (row["column"]) or by index.
  - All timestamps stored as ISO 8601 UTC strings (sortable, readable, no TZ headaches).

Schema overview:
  users              — tech and admin accounts (OAuth or local password)
  clients            — Google Workspace clients managed through the tool
  tech_client_access — which techs can access which clients, at what level
  sessions           — active login sessions (12h absolute, 30min client inactivity)
  scheduled_actions  — time-deferred GAM operations (e.g. 30-day forward removal)

Access levels (tech_client_access.access_level):
  "helpdesk" — card tools only: lookup, forward, delegate, suspend/unsuspend
  "admin"    — everything: helpdesk + terminate, OU moves, scheduled actions, CLI (future)

This maps to two GAM OAuth credential sets per client:
  {clients_root}/{client_id}/gam-config-admin/   — full scope set
  {clients_root}/{client_id}/gam-config-helpdesk/ — reduced scope set
See docs/onboarding-new-client.md for the setup flow.
"""
import asyncio
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import cfg

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Users ──────────────────────────────────────────────────────────────────
-- Created on first login (local password) or first OAuth callback.
-- 'role' here is the tool-wide role (admin can manage other users + clients).
-- Per-client access level is in tech_client_access.
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    role          TEXT NOT NULL DEFAULT 'tech',   -- 'tech' | 'admin'
    auth_provider TEXT NOT NULL DEFAULT 'local',  -- 'local' | 'msal' | 'google'
    password_hash TEXT,                            -- bcrypt hash; NULL for OAuth users
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

-- ── Clients ─────────────────────────────────────────────────────────────────
-- Each client is a Google Workspace tenant managed via GAM.
-- gam_config_admin_path and gam_config_helpdesk_path point to directories
-- containing the GAM credential files for each access tier.
-- These paths are relative to gam.clients_root in config.yaml.
CREATE TABLE IF NOT EXISTS clients (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    domain                   TEXT NOT NULL,
    gam_config_admin_path    TEXT NOT NULL,
    gam_config_helpdesk_path TEXT,              -- nullable if helpdesk not yet set up
    default_terminated_ou    TEXT,              -- e.g. "/Suspended"
    active                   INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT NOT NULL
);

-- ── Tech ↔ Client access ────────────────────────────────────────────────────
-- Explicit grant required — a tech can log in but see no clients until granted.
-- granted_by records the admin's user id for the audit trail.
CREATE TABLE IF NOT EXISTS tech_client_access (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    access_level TEXT NOT NULL DEFAULT 'helpdesk',  -- 'helpdesk' | 'admin'
    granted_at   TEXT NOT NULL,
    granted_by   TEXT REFERENCES users(id),
    PRIMARY KEY (user_id, client_id)
);

-- ── Sessions ─────────────────────────────────────────────────────────────────
-- Cookie value = session id (signed with itsdangerous, so tampering is detected).
-- active_client_id tracks which client the tech is currently working in.
-- last_client_activity enables the 30-min inactivity bounce to dashboard.
CREATE TABLE IF NOT EXISTS sessions (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at            TEXT NOT NULL,
    expires_at            TEXT NOT NULL,         -- absolute 12h expiry
    last_activity         TEXT NOT NULL,         -- any request
    last_client_activity  TEXT,                  -- request inside a client context
    active_client_id      TEXT REFERENCES clients(id)
);

-- ── Scheduled actions ────────────────────────────────────────────────────────
-- Time-deferred GAM operations. The background scheduler (scheduler.py) checks
-- this table on every tick and executes due pending actions.
--
-- action values (v0.2):
--   "remove_forwarding"  — params: {forward_to: "email"}
--   "terminate"          — params: {target_ou, forward_to, delegate_to}
--
-- status flow: pending → completed | failed | cancelled
--
-- created_by stores the tech's email (not id) so the audit trail is readable
-- even if the user record is later deleted. Execution happens as a system
-- principal — it does not require the creating tech's session to still be valid.
CREATE TABLE IF NOT EXISTS scheduled_actions (
    id             TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    created_by     TEXT NOT NULL,        -- tech email
    client_id      TEXT NOT NULL REFERENCES clients(id),
    scheduled_for  TEXT NOT NULL,        -- ISO UTC — when to execute
    action         TEXT NOT NULL,
    target_user    TEXT NOT NULL,        -- GAM subject email
    params         TEXT NOT NULL DEFAULT '{}',  -- JSON blob
    status         TEXT NOT NULL DEFAULT 'pending',
    completed_at   TEXT,
    result         TEXT                  -- JSON blob of GAM output
);

CREATE INDEX IF NOT EXISTS idx_scheduled_pending
    ON scheduled_actions (status, scheduled_for)
    WHERE status = 'pending';

-- ── Client containers ────────────────────────────────────────────────────────
-- Tracks the Docker container lifecycle for each client.
-- status flow: stopped → starting → running → stopped | error
-- last_activity is updated on every GAM command; the scheduler uses it to
-- stop containers that have been idle past the configured timeout.
CREATE TABLE IF NOT EXISTS client_containers (
    client_id      TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    container_name TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'stopped',
    started_at     TEXT,
    last_activity  TEXT NOT NULL DEFAULT '',
    error_msg      TEXT
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(cfg.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Call once at startup."""
    Path(cfg.db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript(SCHEMA)
        for migration in [
            "ALTER TABLE users ADD COLUMN password_hash TEXT",
            "ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
        ]:
            try:
                conn.execute(migration)
            except sqlite3.OperationalError:
                pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


# ── Query helpers (all sync — wrap in asyncio.to_thread at call site) ─────────

def get_user_by_id(user_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def get_user_by_email(email: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()


def upsert_user(email: str, display_name: str, auth_provider: str) -> sqlite3.Row:
    """Create user on first login or update display_name and last_login."""
    with _connect() as conn:
        existing = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET display_name = ?, last_login = ? WHERE email = ?",
                (display_name, now_iso(), email),
            )
            return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        uid = new_id()
        conn.execute(
            "INSERT INTO users (id, email, display_name, role, auth_provider, created_at, last_login) "
            "VALUES (?, ?, ?, 'tech', ?, ?, ?)",
            (uid, email, display_name, auth_provider, now_iso(), now_iso()),
        )
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def get_user_count() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_local_user(
    email: str, display_name: str, password_hash: str, role: str = "admin"
) -> sqlite3.Row:
    uid = new_id()
    ts = now_iso()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO users "
            "(id, email, display_name, role, auth_provider, password_hash, created_at, last_login) "
            "VALUES (?, ?, ?, ?, 'local', ?, ?, ?)",
            (uid, email, display_name, role, password_hash, ts, ts),
        )
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def touch_login(user_id: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso(), user_id))


def get_accessible_clients(user_id: str) -> list[sqlite3.Row]:
    """Return all active clients this user has any access level to."""
    with _connect() as conn:
        return conn.execute(
            """
            SELECT c.*, tca.access_level
            FROM clients c
            JOIN tech_client_access tca ON tca.client_id = c.id
            WHERE tca.user_id = ? AND c.active = 1
            ORDER BY c.name
            """,
            (user_id,),
        ).fetchall()


def get_client_access_level(user_id: str, client_id: str) -> str | None:
    """Return access level for a user/client pair, or None if no access."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT access_level FROM tech_client_access WHERE user_id = ? AND client_id = ?",
            (user_id, client_id),
        ).fetchone()
        return row["access_level"] if row else None


def create_session(user_id: str, expires_at: str) -> str:
    sid = new_id()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at, last_activity) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, user_id, now_iso(), expires_at, now_iso()),
        )
    return sid


def get_session(session_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()


def touch_session(session_id: str, client_id: str | None = None) -> None:
    """Update last_activity (and optionally last_client_activity + active_client_id)."""
    ts = now_iso()
    with _connect() as conn:
        if client_id is not None:
            conn.execute(
                "UPDATE sessions SET last_activity = ?, last_client_activity = ?, "
                "active_client_id = ? WHERE id = ?",
                (ts, ts, client_id, session_id),
            )
        else:
            conn.execute(
                "UPDATE sessions SET last_activity = ? WHERE id = ?",
                (ts, session_id),
            )


def delete_session(session_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


def create_scheduled_action(
    created_by: str,
    client_id: str,
    scheduled_for: str,
    action: str,
    target_user: str,
    params: str = "{}",
) -> str:
    import json
    sid = new_id()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scheduled_actions "
            "(id, created_at, created_by, client_id, scheduled_for, action, target_user, params) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, now_iso(), created_by, client_id, scheduled_for, action, target_user, params),
        )
    return sid


def get_due_actions() -> list[sqlite3.Row]:
    """Return all pending actions whose scheduled_for is in the past."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM scheduled_actions "
            "WHERE status = 'pending' AND scheduled_for <= ? "
            "ORDER BY scheduled_for",
            (now_iso(),),
        ).fetchall()


def complete_action(action_id: str, result: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scheduled_actions SET status = 'completed', completed_at = ?, result = ? "
            "WHERE id = ?",
            (now_iso(), result, action_id),
        )


def fail_action(action_id: str, result: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scheduled_actions SET status = 'failed', completed_at = ?, result = ? "
            "WHERE id = ?",
            (now_iso(), result, action_id),
        )


def cancel_action(action_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scheduled_actions SET status = 'cancelled' WHERE id = ? AND status = 'pending'",
            (action_id,),
        )


# ── Container state helpers ────────────────────────────────────────────────────

def get_client_by_id(client_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM clients WHERE id = ?", (client_id,)
        ).fetchone()


def get_container_state(client_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM client_containers WHERE client_id = ?", (client_id,)
        ).fetchone()


def set_container_state(
    client_id: str,
    status: str,
    container_name: str,
    error_msg: str | None = None,
) -> None:
    ts = now_iso()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO client_containers
                (client_id, container_name, status, started_at, last_activity, error_msg)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_id) DO UPDATE SET
                container_name = excluded.container_name,
                status         = excluded.status,
                started_at     = CASE
                                   WHEN excluded.status = 'running'
                                   THEN excluded.started_at
                                   ELSE started_at
                                 END,
                last_activity  = excluded.last_activity,
                error_msg      = excluded.error_msg
            """,
            (
                client_id,
                container_name,
                status,
                ts if status == "running" else None,
                ts,
                error_msg,
            ),
        )


def touch_container_activity(client_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE client_containers SET last_activity = ? WHERE client_id = ?",
            (now_iso(), client_id),
        )


def get_running_containers() -> list[sqlite3.Row]:
    """Running/starting containers ordered by last_activity ASC (LRU first)."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM client_containers "
            "WHERE status IN ('running', 'starting') "
            "ORDER BY last_activity ASC",
        ).fetchall()


def get_idle_containers(before_ts: str) -> list[sqlite3.Row]:
    """Running containers whose last_activity is before the given timestamp."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM client_containers "
            "WHERE status = 'running' AND last_activity < ?",
            (before_ts,),
        ).fetchall()


def get_all_container_states() -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute("SELECT * FROM client_containers").fetchall()


# ── User management ────────────────────────────────────────────────────────────

def list_users() -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users ORDER BY created_at"
        ).fetchall()


def update_user(user_id: str, display_name: str, role: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET display_name = ?, role = ? WHERE id = ?",
            (display_name, role, user_id),
        )


def set_user_active(user_id: str, active: bool) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET active = ? WHERE id = ?",
            (1 if active else 0, user_id),
        )
        if not active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def set_user_password(user_id: str, password_hash: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id),
        )


def list_user_client_access(user_id: str) -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            """
            SELECT tca.client_id, tca.access_level, c.name AS client_name, c.domain
            FROM tech_client_access tca
            JOIN clients c ON tca.client_id = c.id
            WHERE tca.user_id = ?
            ORDER BY c.name
            """,
            (user_id,),
        ).fetchall()


def set_user_access_bulk(user_id: str, access: list[dict], granted_by: str) -> None:
    """Replace all client access for a user. access = [{"client_id": ..., "access_level": ...}]"""
    ts = now_iso()
    with _connect() as conn:
        conn.execute("DELETE FROM tech_client_access WHERE user_id = ?", (user_id,))
        for entry in access:
            conn.execute(
                "INSERT INTO tech_client_access "
                "(user_id, client_id, access_level, granted_at, granted_by) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, entry["client_id"], entry["access_level"], ts, granted_by),
            )


def list_all_clients() -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            "SELECT id, name, domain FROM clients WHERE active = 1 ORDER BY name"
        ).fetchall()
