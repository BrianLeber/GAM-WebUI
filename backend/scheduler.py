"""
Background scheduler for time-deferred GAM actions.

Runs as an asyncio task launched at app startup (see main.py lifespan).
On each tick, fetches all pending actions whose scheduled_for <= now(),
executes them, and updates their status in the DB.

Design principles:
  - Actions execute as a system principal, not tied to a live session.
    A tech can queue a 30-day forward removal, have their account suspended,
    and the action will still execute. created_by records the email for the
    audit trail, but no session check is performed at execution time.
  - Execution is best-effort per step. A partial failure records which steps
    succeeded and which failed — it does not retry automatically. Alerts
    (email/Slack) are out of scope for v0.2 but the result JSON captures enough
    to surface in the UI.
  - Actions are idempotent where GAM allows it (add forwardingaddress is safe
    to re-run; forward enable checks state first).

Supported action types (v0.2):
  "remove_forwarding"
    params: { "forward_to": "email@domain.com" }

  "terminate"
    params: { "target_ou": "/Suspended", "forward_to": null, "delegate_to": null }

Adding new action types:
  1. Add an entry to ACTION_HANDLERS below
  2. Add the corresponding GamClient method if needed
  3. Add UI for creating the action in frontend/admin.html
"""
import asyncio
import json
import logging

from . import db
from .audit import log_action
from .config import cfg
from .container_manager import stop_idle_containers
from .gam import GamClient

logger = logging.getLogger("scheduler")


async def _execute_action(action_row) -> tuple[bool, str]:
    """
    Dispatch a single scheduled action to the appropriate handler.
    Returns (success, result_json).
    """
    client_id   = action_row["client_id"]
    target_user = action_row["target_user"]
    action_name = action_row["action"]
    params      = json.loads(action_row["params"] or "{}")
    created_by  = action_row["created_by"]

    # Scheduled actions always run with admin credentials
    gam = GamClient.for_access_level(client_id, "admin")

    try:
        if action_name == "remove_forwarding":
            forward_to = params["forward_to"]
            ok, out = await asyncio.to_thread(gam.disable_forwarding, target_user, forward_to)
            result = {"ok": ok, "out": out}

        elif action_name == "terminate":
            target_ou   = params.get("target_ou", "")
            forward_to  = params.get("forward_to")
            delegate_to = params.get("delegate_to")

            # Capture snapshot before changes
            _, info      = await asyncio.to_thread(gam.get_user_status, target_user)
            _, fwd       = await asyncio.to_thread(gam.get_forward_status, target_user)
            _, delegates = await asyncio.to_thread(gam.get_delegates, target_user)

            results = await asyncio.to_thread(
                gam.terminate_user, target_user, target_ou, forward_to, delegate_to
            )
            ok = all(v.get("ok", False) for v in results.values())
            result = {"ok": ok, "steps": results}

        else:
            result = {"ok": False, "error": f"Unknown action type: {action_name}"}
            ok = False

    except Exception as e:
        result = {"ok": False, "error": str(e)}
        ok = False

    result_json = json.dumps(result)

    # Audit log — tech_email is the original creator since there's no live session
    log_action(
        action      = f"[Scheduled] {action_name}",
        tech_email  = created_by,
        client_id   = client_id,
        user        = target_user,
        success     = ok,
        output      = result_json[:500],
    )

    return ok, result_json


async def run_scheduler() -> None:
    """Main scheduler loop. Launched as a background task at startup."""
    logger.info("Scheduler started (interval: %ds)", cfg.scheduler_interval)
    while True:
        await asyncio.sleep(cfg.scheduler_interval)
        try:
            # ── Idle container reaper ──────────────────────────────────────
            idle_timeout = cfg.container_idle_timeout
            stopped = await asyncio.to_thread(stop_idle_containers, idle_timeout)
            if stopped:
                logger.info(
                    "Idle reaper: stopped %d container(s): %s", len(stopped), stopped
                )

            # ── Scheduled GAM actions ──────────────────────────────────────
            due = await asyncio.to_thread(db.get_due_actions)
            if not due:
                continue
            logger.info("Scheduler: %d action(s) due", len(due))
            for row in due:
                logger.info("Executing: %s for %s", row["action"], row["target_user"])
                ok, result_json = await _execute_action(row)
                if ok:
                    await asyncio.to_thread(db.complete_action, row["id"], result_json)
                else:
                    await asyncio.to_thread(db.fail_action, row["id"], result_json)
        except Exception as e:
            logger.exception("Scheduler error: %s", e)
