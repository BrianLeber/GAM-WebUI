"""
GAM-WebUI — FastAPI application entry point.

Route structure:
  /                       → redirect to /dashboard or /login
  /login                  → login page (frontend/login.html)
  /auth/callback/microsoft → MSAL OAuth callback
  /auth/callback/google    → Google OAuth callback
  /logout                  → clear session, redirect to /login
  /dashboard              → client selector (frontend/dashboard.html)
  /client/{client_id}     → per-client admin UI (frontend/admin.html)

  /api/auth/...           → auth API (login URL, logout)
  /api/dashboard/...      → dashboard API (accessible clients)
  /api/client/{id}/...    → per-client GAM operations (all require session + access)

Middleware:
  - Session validation on all /api/client/* routes
  - Client inactivity timeout check on all /api/client/* routes
  - tech_email injected into every audit log entry

Auth mode "none":
  Skips login entirely. Only acceptable for local development.
  A warning is logged at startup. Never deploy with mode=none.
"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db
from .audit import log_action, read_logs, write_termination_record
from .auth import (
    SESSION_COOKIE,
    AuthenticatedUser,
    authenticate_local,
    clear_session,
    get_current_user,
    get_current_user_in_client,
    hash_password,
    make_session,
    parse_session_cookie,
    verify_password,
)

APP_VERSION = "0.1.0"
from .cache import get_ous, get_users
from .config import cfg
from . import container_manager as cm
from .gam import GamClient
from .scheduler import run_scheduler

logger = logging.getLogger("main")
FRONTEND = Path(__file__).parent.parent / "frontend"


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if cfg.auth_mode == "none":
        logger.warning(
            "AUTH MODE IS 'none' — no login required. "
            "This is acceptable for local development only."
        )
    db.init_db()
    if cfg.scheduler_enabled:
        asyncio.create_task(run_scheduler())
    yield


app = FastAPI(title=cfg.app_name, lifespan=lifespan)


# ── Request models ────────────────────────────────────────────────────────────

class ForwardingRequest(BaseModel):
    user:       str
    forward_to: str

class DelegateRequest(BaseModel):
    user:     str
    delegate: str

class MoveOURequest(BaseModel):
    user: str
    ou:   str

class UserRequest(BaseModel):
    user: str

class TerminateRequest(BaseModel):
    user:         str
    confirm_user: str
    target_ou:    str
    forward_to:   str | None = None
    delegate_to:  str | None = None

class VacationRequest(BaseModel):
    user:     str
    subject:  str
    message:  str
    end_date: str | None = None

class ScheduleRequest(BaseModel):
    user:          str
    action:        str
    scheduled_for: str   # ISO UTC
    params:        dict = {}

class LoginRequest(BaseModel):
    email:    str
    password: str

class SetupRequest(BaseModel):
    display_name: str
    email:        str
    password:     str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str

class CreateUserRequest(BaseModel):
    display_name: str
    email:        str
    password:     str
    role:         str = "tech"

class UpdateUserRequest(BaseModel):
    display_name: str
    role:         str

class ResetPasswordRequest(BaseModel):
    password: str

class AccessEntry(BaseModel):
    client_id:    str
    access_level: str

class SetAccessRequest(BaseModel):
    access: list[AccessEntry]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(email: str) -> str:
    return email.strip().lower()


def _dev_user() -> AuthenticatedUser:
    """Fake auth user for mode=none. Never used in production."""
    class _FakeRow(dict):
        def __getitem__(self, k): return self.get(k)

    return AuthenticatedUser(
        _FakeRow({"id": "dev", "email": "dev@local", "display_name": "Dev User", "role": "admin"}),
        _FakeRow({"id": "dev-session", "active_client_id": None}),
    )


async def _auth(request: Request) -> AuthenticatedUser:
    if cfg.auth_mode == "none":
        return _dev_user()
    return await get_current_user(request)


async def _require_admin(request: Request) -> AuthenticatedUser:
    user = await _auth(request)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return user


async def _client_auth(request: Request, client_id: str) -> tuple[AuthenticatedUser, str]:
    if cfg.auth_mode == "none":
        result = _dev_user(), "admin"
    else:
        result = await get_current_user_in_client(request, client_id)
    await asyncio.to_thread(cm.ensure_running, client_id)
    return result


async def _client_access_check(request: Request, client_id: str) -> tuple[AuthenticatedUser, str]:
    """Verify client access without starting the container."""
    if cfg.auth_mode == "none":
        return _dev_user(), "admin"
    return await get_current_user_in_client(request, client_id)


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def root(request: Request):
    if cfg.auth_mode == "none":
        return RedirectResponse("/dashboard")
    count = await asyncio.to_thread(db.get_user_count)
    if count == 0:
        return RedirectResponse("/setup")
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session_id = parse_session_cookie(cookie)
        if session_id:
            session = await asyncio.to_thread(db.get_session, session_id)
            if session:
                return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/setup")
async def setup_page(request: Request):
    count = await asyncio.to_thread(db.get_user_count)
    if count > 0:
        return RedirectResponse("/login")
    return FileResponse(FRONTEND / "setup.html")


@app.get("/login")
async def login_page(request: Request):
    if cfg.auth_mode == "none":
        return RedirectResponse("/dashboard")
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session_id = parse_session_cookie(cookie)
        if session_id:
            session = await asyncio.to_thread(db.get_session, session_id)
            if session:
                return RedirectResponse("/dashboard")
    return FileResponse(FRONTEND / "login.html")


@app.get("/dashboard")
async def dashboard_page(request: Request):
    if cfg.auth_mode != "none":
        try:
            await get_current_user(request)
        except HTTPException:
            return RedirectResponse("/login")
    return FileResponse(FRONTEND / "dashboard.html")


@app.get("/users")
async def users_page(request: Request):
    if cfg.auth_mode != "none":
        try:
            user = await get_current_user(request)
            if user.role != "admin":
                return RedirectResponse("/dashboard")
        except HTTPException:
            return RedirectResponse("/login")
    return FileResponse(FRONTEND / "users.html")


@app.get("/client/{client_id}")
async def admin_page(client_id: str, request: Request):
    if cfg.auth_mode != "none":
        try:
            await get_current_user(request)
        except HTTPException:
            return RedirectResponse("/login")
    return FileResponse(FRONTEND / "admin.html")


@app.post("/logout")
async def logout(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session_id = parse_session_cookie(cookie)
        if session_id:
            await asyncio.to_thread(db.delete_session, session_id)
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── Auth API ──────────────────────────────────────────────────────────────────

@app.get("/api/version")
async def api_version():
    return {"version": APP_VERSION}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    user = await _auth(request)
    return {"email": user.email, "displayName": user.display_name, "role": user.role}


@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordRequest, request: Request):
    user = await get_current_user(request)
    user_row = await asyncio.to_thread(db.get_user_by_id, user.id)
    if not user_row or user_row["auth_provider"] != "local" or not user_row["password_hash"]:
        raise HTTPException(400, "Password change is not available for this account type.")
    if not verify_password(req.current_password, user_row["password_hash"]):
        raise HTTPException(400, "Current password is incorrect.")
    if len(req.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters.")
    pw_hash = hash_password(req.new_password)
    await asyncio.to_thread(db.set_user_password, user.id, pw_hash)
    return {"ok": True}


@app.post("/api/auth/setup")
async def api_setup(req: SetupRequest):
    """Create the first admin account. Fails if any users already exist."""
    count = await asyncio.to_thread(db.get_user_count)
    if count > 0:
        raise HTTPException(400, "Setup already complete. Use the login page.")
    email = req.email.strip().lower()
    if not email or not req.password:
        raise HTTPException(400, "Email and password are required.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    pw_hash = hash_password(req.password)
    user = await asyncio.to_thread(
        db.create_local_user, email, req.display_name.strip() or email, pw_hash, "admin"
    )
    session_id = await asyncio.to_thread(make_session, user["id"])
    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax",
                    secure=cfg.secure_cookies, max_age=cfg.session_max_age)
    return resp


@app.post("/api/auth/login")
async def api_login(req: LoginRequest):
    """Validate local credentials and create a session."""
    user = await asyncio.to_thread(authenticate_local, req.email, req.password)
    if not user:
        raise HTTPException(401, "Invalid email or password.")
    session_id = await asyncio.to_thread(make_session, user["id"])
    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax",
                    secure=cfg.secure_cookies, max_age=cfg.session_max_age)
    return resp


# Future: /auth/callback/microsoft — MSAL token exchange
# Future: /auth/callback/google    — Google token exchange


# ── Dashboard API ─────────────────────────────────────────────────────────────

@app.get("/api/dashboard/clients")
async def dashboard_clients(request: Request):
    user  = await _auth(request)
    rows  = await asyncio.to_thread(db.get_accessible_clients, user.id)
    # Build a status map from the DB in one query (avoids N docker-ps calls)
    states = await asyncio.to_thread(db.get_all_container_states)
    state_map = {s["client_id"]: s["status"] for s in states}
    clients = []
    for r in rows:
        d = dict(r)
        d["container_status"] = state_map.get(r["id"], "stopped")
        clients.append(d)
    return {"clients": clients}


# ── Container management API ──────────────────────────────────────────────────

@app.post("/api/client/{client_id}/container/start")
async def api_container_start(client_id: str, request: Request):
    """Start the client container (or confirm it is already running)."""
    await _client_auth(request, client_id)  # verifies access and ensures container is running
    cst = await asyncio.to_thread(cm.status, client_id)
    return {"client_id": client_id, "status": cst, "ok": True, "message": "running"}


@app.get("/api/client/{client_id}/container/status")
async def api_container_status(client_id: str, request: Request):
    """Return the current container status plus client metadata."""
    await _client_access_check(request, client_id)
    cst = await asyncio.to_thread(cm.status, client_id)
    row = await asyncio.to_thread(db.get_client_by_id, client_id)
    return {
        "client_id": client_id,
        "status":    cst,
        "name":      row["name"]   if row else client_id,
        "domain":    row["domain"] if row else "",
    }


@app.post("/api/client/{client_id}/container/stop")
async def api_container_stop(client_id: str, request: Request):
    """Manually stop a client container (admin only)."""
    _, access_level = await _client_auth(request, client_id)
    if access_level != "admin":
        raise HTTPException(403, "Admin access required to stop containers.")
    ok, msg = await asyncio.to_thread(cm.stop, client_id)
    return {"client_id": client_id, "status": "stopped" if ok else "error", "message": msg}


# ── Per-client API ────────────────────────────────────────────────────────────
# All routes below require a valid session + client access.
# The GamClient is instantiated per-request using the tech's access_level,
# which determines which credential tier (admin/helpdesk) is used.

@app.get("/api/client/{client_id}/users")
async def client_users(client_id: str, request: Request):
    user, access_level = await _client_auth(request, client_id)
    gam = GamClient.for_access_level(client_id, access_level)
    ok, emails = await get_users(client_id, gam)
    return {"ready": ok, "users": emails}


@app.get("/api/client/{client_id}/ous")
async def client_ous(client_id: str, request: Request):
    user, access_level = await _client_auth(request, client_id)
    gam = GamClient.for_access_level(client_id, access_level)
    ok, ous = await get_ous(client_id, gam)
    return {"ready": ok, "ous": ous}


@app.get("/api/client/{client_id}/user/status")
async def user_status(client_id: str, target_user: str, request: Request):
    user, access_level = await _client_auth(request, client_id)
    gam = GamClient.for_access_level(client_id, access_level)
    ok, info      = await asyncio.to_thread(gam.get_user_status, target_user)
    if not ok:
        raise HTTPException(404, info.get("error", "User not found"))
    _, fwd       = await asyncio.to_thread(gam.get_forward_status, target_user)
    _, delegates = await asyncio.to_thread(gam.get_delegates, target_user)
    _, vacation  = await asyncio.to_thread(gam.get_vacation, target_user)
    return {"user": target_user, "info": info, "forwarding": fwd, "delegates": delegates, "vacation": vacation}


@app.get("/api/client/{client_id}/logs")
async def client_logs(client_id: str, request: Request, limit: int = 50):
    await _client_auth(request, client_id)
    return {"entries": read_logs(client_id, limit)}


# ── Forwarding ────────────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/forwarding/add")
async def add_forwarding(client_id: str, req: ForwardingRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject, target = _norm(req.user), _norm(req.forward_to)
    if subject == target:
        return log_action("Enable Forwarding", auth_user.email, client_id, subject,
                          False, "Subject and target cannot be the same address", target)
    gam = GamClient.for_access_level(client_id, access_level)
    _, fwd = await asyncio.to_thread(gam.get_forward_status, subject)
    if fwd["enabled"] and _norm(fwd.get("address") or "") == target:
        return log_action("Enable Forwarding", auth_user.email, client_id, subject,
                          True, f"Already forwarding to {target} — no change needed.",
                          target, skipped=True, skip_reason="Already forwarding to this address")
    ok, out = await asyncio.to_thread(gam.enable_forwarding, subject, target)
    return log_action("Enable Forwarding", auth_user.email, client_id, subject, ok, out, target)


@app.post("/api/client/{client_id}/forwarding/remove")
async def remove_forwarding(client_id: str, req: ForwardingRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject, target = _norm(req.user), _norm(req.forward_to)
    gam = GamClient.for_access_level(client_id, access_level)
    _, fwd = await asyncio.to_thread(gam.get_forward_status, subject)
    if not fwd["enabled"]:
        return log_action("Disable Forwarding", auth_user.email, client_id, subject,
                          True, "Forwarding is already off — no change needed.",
                          target, skipped=True, skip_reason="Forwarding already off")
    ok, out = await asyncio.to_thread(gam.disable_forwarding, subject, target)
    return log_action("Disable Forwarding", auth_user.email, client_id, subject, ok, out, target)


# ── Delegation ────────────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/delegate/add")
async def add_delegate(client_id: str, req: DelegateRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject, target = _norm(req.user), _norm(req.delegate)
    if subject == target:
        return log_action("Add Delegate", auth_user.email, client_id, subject,
                          False, "Subject and delegate cannot be the same address", target)
    gam = GamClient.for_access_level(client_id, access_level)
    _, delegates = await asyncio.to_thread(gam.get_delegates, subject)
    if target in delegates:
        return log_action("Add Delegate", auth_user.email, client_id, subject,
                          True, f"{target} is already a delegate — no change needed.",
                          target, skipped=True, skip_reason="Already delegated")
    ok, out = await asyncio.to_thread(gam.add_delegate, subject, target)
    return log_action("Add Delegate", auth_user.email, client_id, subject, ok, out, target)


@app.post("/api/client/{client_id}/delegate/remove")
async def remove_delegate(client_id: str, req: DelegateRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject, target = _norm(req.user), _norm(req.delegate)
    gam = GamClient.for_access_level(client_id, access_level)
    _, delegates = await asyncio.to_thread(gam.get_delegates, subject)
    if target not in delegates:
        return log_action("Remove Delegate", auth_user.email, client_id, subject,
                          True, f"{target} is not currently a delegate — no change needed.",
                          target, skipped=True, skip_reason="Not currently delegated")
    ok, out = await asyncio.to_thread(gam.remove_delegate, subject, target)
    return log_action("Remove Delegate", auth_user.email, client_id, subject, ok, out, target)


# ── Vacation / OOO ───────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/vacation/set")
async def set_vacation(client_id: str, req: VacationRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject = req.subject.strip()
    message = req.message.strip()
    if not subject or not message:
        return log_action("Enable Vacation", auth_user.email, client_id, _norm(req.user),
                          False, "Subject and message are required.")
    gam = GamClient.for_access_level(client_id, access_level)
    ok, out = await asyncio.to_thread(
        gam.set_vacation, _norm(req.user), subject, message, req.end_date or None
    )
    return log_action("Enable Vacation", auth_user.email, client_id, _norm(req.user), ok, out,
                      req.end_date or "indefinite")


@app.post("/api/client/{client_id}/vacation/clear")
async def clear_vacation(client_id: str, req: UserRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    gam = GamClient.for_access_level(client_id, access_level)
    ok, out = await asyncio.to_thread(gam.disable_vacation, _norm(req.user))
    return log_action("Disable Vacation", auth_user.email, client_id, _norm(req.user), ok, out)


# ── Suspend / Unsuspend ───────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/user/suspend")
async def suspend(client_id: str, req: UserRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject = _norm(req.user)
    gam = GamClient.for_access_level(client_id, access_level)
    _, info = await asyncio.to_thread(gam.get_user_status, subject)
    if info.get("suspended"):
        return log_action("Suspend", auth_user.email, client_id, subject,
                          True, "Already suspended — no change needed.",
                          skipped=True, skip_reason="Already suspended")
    ok, out = await asyncio.to_thread(gam.suspend_user, subject)
    return log_action("Suspend", auth_user.email, client_id, subject, ok, out)


@app.post("/api/client/{client_id}/user/unsuspend")
async def unsuspend(client_id: str, req: UserRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    subject = _norm(req.user)
    gam = GamClient.for_access_level(client_id, access_level)
    _, info = await asyncio.to_thread(gam.get_user_status, subject)
    if not info.get("suspended"):
        return log_action("Unsuspend", auth_user.email, client_id, subject,
                          True, "Not suspended — no change needed.",
                          skipped=True, skip_reason="Not suspended")
    ok, out = await asyncio.to_thread(gam.unsuspend_user, subject)
    return log_action("Unsuspend", auth_user.email, client_id, subject, ok, out)


# ── Move OU ───────────────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/user/move-ou")
async def move_ou(client_id: str, req: MoveOURequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    # OU moves are admin-only
    if access_level != "admin":
        raise HTTPException(403, "OU moves require admin access.")
    subject = _norm(req.user)
    gam = GamClient.for_access_level(client_id, "admin")
    ok, out = await asyncio.to_thread(gam.move_user_ou, subject, req.ou.strip())
    return log_action("Move OU", auth_user.email, client_id, subject, ok, out, req.ou.strip())


# ── Terminate ─────────────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/user/terminate")
async def terminate(client_id: str, req: TerminateRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    if access_level != "admin":
        raise HTTPException(403, "Termination requires admin access.")

    subject      = _norm(req.user)
    confirm_user = _norm(req.confirm_user)
    if subject != confirm_user:
        raise HTTPException(400, "Confirmation username does not match.")
    if not req.target_ou:
        raise HTTPException(400, "Target OU is required.")

    forward_to  = _norm(req.forward_to)  if req.forward_to  else None
    delegate_to = _norm(req.delegate_to) if req.delegate_to else None

    gam = GamClient.for_access_level(client_id, "admin")

    # Snapshot before any changes
    _, info      = await asyncio.to_thread(gam.get_user_status, subject)
    _, fwd       = await asyncio.to_thread(gam.get_forward_status, subject)
    _, delegates = await asyncio.to_thread(gam.get_delegates, subject)
    snapshot = {"info": info, "forwarding": fwd, "delegates": delegates}

    results = await asyncio.to_thread(
        gam.terminate_user, subject, req.target_ou, forward_to, delegate_to
    )

    write_termination_record(
        tech_email  = auth_user.email,
        client_id   = client_id,
        user        = subject,
        snapshot    = snapshot,
        actions     = {"targetOU": req.target_ou, "forwardTo": forward_to, "delegateTo": delegate_to},
        results     = results,
    )

    overall_ok = all(v.get("ok", False) for v in results.values())
    summary    = "\n".join(
        f"{k}: {'OK' if v.get('ok') else 'FAIL'} — {v.get('out','')[:120]}"
        for k, v in results.items()
    )
    return log_action("Terminate User", auth_user.email, client_id,
                      subject, overall_ok, summary, req.target_ou)


# ── Scheduled actions ─────────────────────────────────────────────────────────

@app.post("/api/client/{client_id}/schedule")
async def schedule_action(client_id: str, req: ScheduleRequest, request: Request):
    auth_user, access_level = await _client_auth(request, client_id)
    if access_level != "admin":
        raise HTTPException(403, "Scheduling requires admin access.")
    sid = await asyncio.to_thread(
        db.create_scheduled_action,
        auth_user.email, client_id,
        req.scheduled_for, req.action,
        _norm(req.user), json.dumps(req.params),
    )
    return {"id": sid, "status": "scheduled"}


@app.get("/api/client/{client_id}/schedule")
async def list_scheduled(client_id: str, request: Request):
    await _client_auth(request, client_id)
    # TODO: add db.list_scheduled_for_client(client_id)
    return {"actions": []}


# ── Admin: user management ────────────────────────────────────────────────────
# All routes require role=admin.

@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    await _require_admin(request)
    rows = await asyncio.to_thread(db.list_users)
    return {"users": [dict(r) for r in rows]}


@app.get("/api/admin/clients")
async def admin_list_clients(request: Request):
    await _require_admin(request)
    rows = await asyncio.to_thread(db.list_all_clients)
    return {"clients": [dict(r) for r in rows]}


@app.post("/api/admin/users")
async def admin_create_user(req: CreateUserRequest, request: Request):
    admin = await _require_admin(request)
    email = req.email.strip().lower()
    if not email or not req.password:
        raise HTTPException(400, "Email and password are required.")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    if req.role not in ("admin", "tech"):
        raise HTTPException(400, "Role must be 'admin' or 'tech'.")
    existing = await asyncio.to_thread(db.get_user_by_email, email)
    if existing:
        raise HTTPException(409, "A user with that email already exists.")
    pw_hash = hash_password(req.password)
    user = await asyncio.to_thread(
        db.create_local_user, email, req.display_name.strip() or email, pw_hash, req.role
    )
    return {"ok": True, "user": dict(user)}


@app.patch("/api/admin/users/{user_id}")
async def admin_update_user(user_id: str, req: UpdateUserRequest, request: Request):
    admin = await _require_admin(request)
    if user_id == admin.id and req.role != "admin":
        raise HTTPException(400, "You cannot remove your own admin role.")
    if req.role not in ("admin", "tech"):
        raise HTTPException(400, "Role must be 'admin' or 'tech'.")
    target = await asyncio.to_thread(db.get_user_by_id, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    await asyncio.to_thread(db.update_user, user_id, req.display_name.strip(), req.role)
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
async def admin_deactivate_user(user_id: str, request: Request):
    admin = await _require_admin(request)
    if user_id == admin.id:
        raise HTTPException(400, "You cannot deactivate your own account.")
    target = await asyncio.to_thread(db.get_user_by_id, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    await asyncio.to_thread(db.set_user_active, user_id, False)
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/reactivate")
async def admin_reactivate_user(user_id: str, request: Request):
    await _require_admin(request)
    target = await asyncio.to_thread(db.get_user_by_id, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    await asyncio.to_thread(db.set_user_active, user_id, True)
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/password")
async def admin_reset_password(user_id: str, req: ResetPasswordRequest, request: Request):
    await _require_admin(request)
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    target = await asyncio.to_thread(db.get_user_by_id, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    pw_hash = hash_password(req.password)
    await asyncio.to_thread(db.set_user_password, user_id, pw_hash)
    return {"ok": True}


@app.get("/api/admin/users/{user_id}/access")
async def admin_get_user_access(user_id: str, request: Request):
    await _require_admin(request)
    rows = await asyncio.to_thread(db.list_user_client_access, user_id)
    return {"access": [dict(r) for r in rows]}


@app.put("/api/admin/users/{user_id}/access")
async def admin_set_user_access(user_id: str, req: SetAccessRequest, request: Request):
    admin = await _require_admin(request)
    target = await asyncio.to_thread(db.get_user_by_id, user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    valid_levels = {"admin", "helpdesk"}
    access = []
    for entry in req.access:
        if entry.access_level not in valid_levels:
            raise HTTPException(400, f"Invalid access level: {entry.access_level}")
        access.append({"client_id": entry.client_id, "access_level": entry.access_level})
    await asyncio.to_thread(db.set_user_access_bulk, user_id, access, admin.id)
    return {"ok": True}


# ── Static assets ─────────────────────────────────────────────────────────────

# Serve any files in frontend/static/ (CSS, JS, images) if we add them later
# app.mount("/static", StaticFiles(directory=str(FRONTEND / "static")), name="static")
