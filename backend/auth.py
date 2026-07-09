"""
Authentication and session management.

Active auth implementation: local email/password (bcrypt).

Session cookie:
  - HTTP-only, SameSite=Lax
  - Signed with itsdangerous (tampered cookies are rejected before any DB lookup)
  - Set Secure=True via config when running behind HTTPS (session.secure_cookies)
  - Session record in SQLite carries expiry + last_activity timestamps

Two timeout tiers:
  - 12-hour absolute expiry (cfg.session_max_age) — re-login required
  - 30-minute client inactivity (cfg.client_inactivity_timeout) — bounced to
    dashboard, not logged out. The 12-hour clock keeps ticking.

OAuth stubs (not yet active):
  - microsoft_login_url / microsoft_callback — requires Azure app registration
  - google_login_url / google_callback — Google OAuth for identity only

TODO (v0.2):
  - Wire up MSAL flow (Microsoft)
  - Wire up Google OAuth flow
  - Implement domain validation against allowed_domains
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Cookie, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, Signer

from . import db
from .config import cfg


# ── Session helpers ────────────────────────────────────────────────────────────

SESSION_COOKIE = "gam_session"


def _expires_at() -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=cfg.session_max_age)
    ).isoformat()


def _signer() -> Signer:
    return Signer(cfg.secret_key, salt="gam-session")


def make_session(user_id: str) -> str:
    """Create a session in the DB and return a signed cookie value."""
    session_id = db.create_session(user_id, _expires_at())
    return _signer().sign(session_id).decode()


def parse_session_cookie(cookie: str) -> str | None:
    """Verify signature and return the raw session ID, or None if tampered."""
    try:
        return _signer().unsign(cookie).decode()
    except BadSignature:
        return None


def clear_session(cookie_value: str) -> None:
    """Delete the session identified by a signed cookie value."""
    session_id = parse_session_cookie(cookie_value)
    if session_id:
        db.delete_session(session_id)


# ── Request-level auth dependency ─────────────────────────────────────────────

class AuthenticatedUser:
    """Resolved from the session cookie on every authenticated request."""
    def __init__(self, user_row, session_row):
        self.id           = user_row["id"]
        self.email        = user_row["email"]
        self.display_name = user_row["display_name"]
        self.role         = user_row["role"]   # "tech" | "admin"
        self.session_id   = session_row["id"]
        self.active_client_id = session_row["active_client_id"]


async def get_current_user(request: Request) -> AuthenticatedUser:
    """
    FastAPI dependency. Raises 401/403 if session is missing, expired, or invalid.
    Call as: user: AuthenticatedUser = Depends(get_current_user)
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_id = parse_session_cookie(cookie)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    import asyncio
    session = await asyncio.to_thread(db.get_session, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session not found")

    now = datetime.now(timezone.utc).isoformat()
    if session["expires_at"] < now:
        await asyncio.to_thread(db.delete_session, session_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    user = await asyncio.to_thread(db.get_user_by_id, session["user_id"])
    if not user or not user["active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    await asyncio.to_thread(db.touch_session, session_id)
    return AuthenticatedUser(user, session)


async def get_current_user_in_client(
    request: Request,
    client_id: str,
) -> tuple[AuthenticatedUser, str]:
    """
    Dependency for client-scoped requests.
    Returns (user, access_level) or raises 403.
    Also enforces the client inactivity timeout.
    """
    import asyncio

    user = await get_current_user(request)

    # Check client access
    access_level = await asyncio.to_thread(
        db.get_client_access_level, user.id, client_id
    )
    if not access_level:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have access to this client.")

    # Enforce inactivity timeout — only applies after the user has previously
    # entered a client context. If last_client_activity is None they haven't
    # opened any client yet this session, so there is nothing to time out.
    session = await asyncio.to_thread(db.get_session, user.session_id)
    last_client_activity = session["last_client_activity"]
    if last_client_activity:
        elapsed = (
            datetime.now(timezone.utc) -
            datetime.fromisoformat(last_client_activity)
        ).total_seconds()
        if elapsed > cfg.client_inactivity_timeout:
            await asyncio.to_thread(db.touch_session, user.session_id, None)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Client session timed out due to inactivity. Return to dashboard.",
                headers={"X-Redirect": "/dashboard"},
            )

    # Update client activity timestamp
    await asyncio.to_thread(db.touch_session, user.session_id, client_id)

    return user, access_level


# ── Local password auth ───────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def authenticate_local(email: str, password: str) -> sqlite3.Row | None:
    """Return the user row if credentials are valid, else None."""
    user = db.get_user_by_email(email.strip().lower())
    if not user or not user["active"] or user["auth_provider"] != "local" or not user["password_hash"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    db.touch_login(user["id"])
    return user


# ── OAuth stubs ───────────────────────────────────────────────────────────────
# TODO: implement in v0.2

async def microsoft_login_url(state: str) -> str:
    """
    Return the Microsoft OAuth authorization URL.
    Requires: msal package, config.auth.msal.{tenant_id, client_id, redirect_uri}
    Scopes needed: openid, profile, email (identity only — no MS Graph for GAM ops)
    """
    raise NotImplementedError("MSAL login not yet implemented")


async def microsoft_callback(code: str, state: str) -> tuple[str, str]:
    """
    Exchange code for tokens, return (email, display_name).
    Validates that email domain is in cfg.allowed_domains.
    """
    raise NotImplementedError("MSAL callback not yet implemented")


async def google_login_url(state: str) -> str:
    """
    Return the Google OAuth authorization URL.
    Scopes: openid, email, profile (identity only).
    Google OAuth here is for IDENTITY only — not Admin SDK access.
    Admin SDK access is handled by per-client GAM credentials.
    """
    raise NotImplementedError("Google OAuth login not yet implemented")


async def google_callback(code: str, state: str) -> tuple[str, str]:
    """Exchange code for tokens, return (email, display_name)."""
    raise NotImplementedError("Google OAuth callback not yet implemented")
