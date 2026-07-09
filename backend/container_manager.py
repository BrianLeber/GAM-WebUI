"""
Docker container lifecycle manager for per-client GAM containers.

Uses the Docker Python SDK (docker package) to communicate with the daemon
via /var/run/docker.sock — no docker CLI binary required inside the container.

Each client gets one container named gam-client-{client_id}.
The container stays alive via `sleep infinity`; GAM commands run via exec_run.

Credential tiers (admin/helpdesk) are selected per-command by passing
  GAMCONFIGDIR=<path>
as an environment variable to exec_run, so both tier directories are
available in the same container.

Concurrent cap: when max_concurrent containers are running and a new client
needs to start, the least-recently-used container is stopped first.
"""
import logging
import re
from datetime import datetime, timedelta, timezone

import docker
import docker.errors

from . import db
from .config import cfg

logger = logging.getLogger("container_manager")


def _client() -> docker.DockerClient:
    return docker.from_env()


def _sanitize(client_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "-", client_id).lower()


def container_name(client_id: str) -> str:
    return f"gam-client-{_sanitize(client_id)}"


def is_running(client_id: str) -> bool:
    """Ask Docker whether the container is actually running right now."""
    name = container_name(client_id)
    try:
        containers = _client().containers.list(
            filters={"name": name, "status": "running"}
        )
        return any(ct.name == name for ct in containers)
    except Exception:
        return False


def status(client_id: str) -> str:
    """Return 'running', 'starting', 'stopped', or 'error'."""
    if is_running(client_id):
        return "running"
    row = db.get_container_state(client_id)
    if row and row["status"] == "error":
        return "error"
    if row and row["status"] == "starting":
        return "starting"
    return "stopped"


def exec_in_container(
    client_id: str,
    cmd: list[str],
    env: dict | None = None,
) -> tuple[int, str, str]:
    """
    Run a command in the client's container via exec.
    Returns (exit_code, stdout, stderr).
    """
    name = container_name(client_id)
    try:
        container = _client().containers.get(name)
        exit_code, (stdout_bytes, stderr_bytes) = container.exec_run(
            cmd,
            environment=env or {},
            demux=True,
        )
        stdout = stdout_bytes.decode("utf-8", errors="replace").strip() if stdout_bytes else ""
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip() if stderr_bytes else ""
        return exit_code, stdout, stderr
    except docker.errors.NotFound:
        return 1, "", f"Container '{name}' not found"
    except Exception as e:
        return 1, "", str(e)


def start(client_id: str) -> tuple[bool, str]:
    """Start the client container. Returns (success, message)."""
    name = container_name(client_id)

    if is_running(client_id):
        db.touch_container_activity(client_id)
        return True, "already running"

    volumes: dict = {}
    data_volume    = cfg.container_data_volume
    host_data_path = cfg.container_host_data_path
    gam_host_path  = cfg.container_gam_host_path

    if data_volume:
        # Named Docker volumes cannot be partially mounted — the whole volume is
        # accessible from the client container. For tighter isolation, use
        # host_data_path (bind mount) instead.
        volumes[data_volume] = {"bind": "/data", "mode": "rw"}
    elif host_data_path:
        # Mount only this client's credential directory, not the entire data volume.
        # GAM gets write access to refresh OAuth tokens without touching the DB,
        # audit logs, or other clients' credentials.
        from pathlib import Path as _Path
        client_dir = _Path(host_data_path) / "clients" / client_id
        client_dir.mkdir(parents=True, exist_ok=True)
        volumes[str(client_dir)] = {"bind": "/client-data", "mode": "rw"}

    if gam_host_path:
        volumes[gam_host_path] = {"bind": "/opt/gam7", "mode": "ro"}

    db.set_container_state(client_id, "starting", name)

    try:
        _client().containers.run(
            cfg.container_image,
            ["sleep", "infinity"],
            name=name,
            detach=True,
            remove=True,
            volumes=volumes,
        )
        db.set_container_state(client_id, "running", name)
        logger.info("Started container %s for client %s", name, client_id)
        return True, "started"

    except docker.errors.APIError as e:
        msg = str(e)
        if "already in use" in msg or "Conflict" in msg:
            if is_running(client_id):
                db.set_container_state(client_id, "running", name)
                return True, "container already running"
        db.set_container_state(client_id, "error", name, error_msg=msg[:500])
        logger.error("Failed to start container %s: %s", name, msg)
        return False, msg

    except Exception as e:
        msg = str(e)
        db.set_container_state(client_id, "error", name, error_msg=msg[:500])
        logger.error("Failed to start container %s: %s", name, msg)
        return False, msg


def stop(client_id: str) -> tuple[bool, str]:
    """Stop the client container."""
    name = container_name(client_id)
    try:
        container = _client().containers.get(name)
        container.stop(timeout=10)
        db.set_container_state(client_id, "stopped", name)
        logger.info("Stopped container %s for client %s", name, client_id)
        return True, "stopped"
    except docker.errors.NotFound:
        db.set_container_state(client_id, "stopped", name)
        return True, "not running"
    except Exception as e:
        return False, str(e)


def ensure_running(client_id: str) -> tuple[bool, str]:
    """
    Guarantee the container is running before a GAM command.
    Enforces the concurrent cap by stopping the LRU container when needed.
    """
    if is_running(client_id):
        db.touch_container_activity(client_id)
        return True, "running"

    running_rows = db.get_running_containers()
    running_ids  = [r["client_id"] for r in running_rows]
    max_c        = cfg.container_max_concurrent

    # Verify DB state against Docker — DB can be stale after an external kill
    actually_running = [cid for cid in running_ids if is_running(cid)]

    while len(actually_running) >= max_c:
        lru = actually_running.pop(0)
        logger.info("Cap=%d: evicting LRU container for client %s", max_c, lru)
        stop(lru)

    return start(client_id)


def stop_idle_containers(idle_seconds: int) -> list[str]:
    """
    Stop containers idle for longer than idle_seconds.
    Returns the list of client_ids stopped.
    """
    threshold = (
        datetime.now(timezone.utc) - timedelta(seconds=idle_seconds)
    ).isoformat()

    rows    = db.get_idle_containers(threshold)
    stopped = []
    for row in rows:
        client_id = row["client_id"]
        if is_running(client_id):
            ok, _ = stop(client_id)
            if ok:
                stopped.append(client_id)
    return stopped
