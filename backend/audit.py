"""
Audit logging.

Every action is written to two places:
  1. logs/commands.jsonl  — append-only JSONL, one entry per action
  2. logs/terminations/   — one JSON file per termination (full snapshot + steps)

Every log entry includes:
  - ts          — ISO UTC timestamp
  - tech_email  — the authenticated user who performed the action (critical for MSP)
  - client_id   — which client's GAM config was used
  - action      — human-readable action name
  - user        — the Google Workspace user being acted on
  - target      — secondary email (forward-to, delegate, etc.) if applicable
  - success     — bool
  - skipped     — bool (pre-check determined no action needed)
  - skip_reason — string if skipped
  - output      — raw GAM output

The termination record additionally stores a full pre-termination snapshot
of the user (info, forwarding, delegates) for audit/recovery reference.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import cfg


def _logs_dir() -> Path:
    p = Path(cfg.logs_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _term_dir() -> Path:
    p = _logs_dir() / "terminations"
    p.mkdir(exist_ok=True)
    return p


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_action(
    action:      str,
    tech_email:  str,
    client_id:   str,
    user:        str,
    success:     bool,
    output:      str,
    target:      str | None = None,
    skipped:     bool = False,
    skip_reason: str | None = None,
) -> dict:
    entry = {
        "id":          str(uuid.uuid4()),
        "ts":          _now(),
        "tech_email":  tech_email,
        "client_id":   client_id,
        "action":      action,
        "user":        user,
        "target":      target,
        "success":     success,
        "skipped":     skipped,
        "skip_reason": skip_reason,
        "output":      output,
    }
    with (_logs_dir() / "commands.jsonl").open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def read_logs(client_id: str, limit: int = 50) -> list[dict]:
    """Return the most recent `limit` log entries for a given client."""
    path = _logs_dir() / "commands.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in reversed(path.read_text().splitlines()[-limit * 2:]):
        try:
            e = json.loads(line)
            if e.get("client_id") == client_id:
                entries.append(e)
        except Exception:
            pass
        if len(entries) >= limit:
            break
    return entries


def write_termination_record(
    tech_email:  str,
    client_id:   str,
    user:        str,
    snapshot:    dict,
    actions:     dict,
    results:     dict,
) -> Path:
    ts = datetime.now(timezone.utc)
    record = {
        "terminatedAt": ts.isoformat(),
        "techEmail":    tech_email,
        "clientId":     client_id,
        "user":         user,
        "snapshot":     snapshot,
        "actions":      actions,
        "results":      results,
    }
    fname = f"{ts.strftime('%Y-%m-%d_%H-%M-%S')}_{user.replace('@','_at_')}.json"
    path  = _term_dir() / client_id
    path.mkdir(exist_ok=True)
    (path / fname).write_text(json.dumps(record, indent=2))
    return path / fname
