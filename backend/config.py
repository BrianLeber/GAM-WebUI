"""
Application config loader.

Reads config.yaml (path set via GAM_WEBUI_CONFIG env var, default ./config.yaml).
Environment variables override yaml values using double-underscore as separator:
  APP__SECRET_KEY=xyz  →  config.app.secret_key = "xyz"

Per-client settings (domain, default OU, GAM config path, access levels) live
in the SQLite database, NOT here. This file is app-level config only.
"""
import os
from pathlib import Path
from typing import Any

import yaml


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Copy config.example.yaml to {path} and fill in values."
        )
    with path.open() as f:
        return yaml.safe_load(f) or {}


def _deep_get(d: dict, *keys, default=None) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


class Config:
    def __init__(self, data: dict):
        self._data = data

    def get(self, *keys, default=None):
        return _deep_get(self._data, *keys, default=default)

    # ── Shortcuts ─────────────────────────────────────────────────────────

    @property
    def app_name(self) -> str:
        return self.get("app", "name", default="GAM WebUI")

    @property
    def secret_key(self) -> str:
        key = self.get("app", "secret_key", default="")
        if not key or key == "CHANGE_ME":
            raise ValueError("app.secret_key must be set in config.yaml")
        return key

    @property
    def db_path(self) -> str:
        return self.get("database", "path", default="./data/db.sqlite")

    @property
    def gam_path(self) -> str:
        return os.environ.get("GAM_PATH") or self.get("gam", "path", default="/opt/gam7/gam")

    @property
    def clients_root(self) -> str:
        return self.get("gam", "clients_root", default="./data/clients")

    @property
    def auth_mode(self) -> str:
        # "none" is only acceptable for local dev; enforced in main.py startup check
        return self.get("auth", "mode", default="none")

    @property
    def allowed_domains(self) -> list[str]:
        return self.get("auth", "allowed_domains", default=[])

    @property
    def msal_config(self) -> dict:
        return self.get("auth", "msal", default={})

    @property
    def google_oauth_config(self) -> dict:
        return self.get("auth", "google", default={})

    @property
    def session_max_age(self) -> int:
        return self.get("session", "max_age_seconds", default=43200)  # 12h

    @property
    def client_inactivity_timeout(self) -> int:
        return self.get("session", "client_inactivity_seconds", default=1800)  # 30min

    @property
    def secure_cookies(self) -> bool:
        """Set true when running behind HTTPS. Tells browsers not to send the cookie over HTTP."""
        return bool(self.get("session", "secure_cookies", default=False))

    @property
    def scheduler_enabled(self) -> bool:
        return self.get("scheduler", "enabled", default=True)

    @property
    def scheduler_interval(self) -> int:
        return self.get("scheduler", "check_interval_minutes", default=5) * 60

    @property
    def logs_dir(self) -> str:
        return self.get("logs", "dir", default="./data/logs")

    # ── Container management ───────────────────────────────────────────────

    @property
    def container_image(self) -> str:
        return self.get("containers", "image", default="gam-client:latest")

    @property
    def container_max_concurrent(self) -> int:
        return self.get("containers", "max_concurrent", default=5)

    @property
    def container_idle_timeout(self) -> int:
        return self.get("containers", "idle_timeout_minutes", default=30) * 60

    @property
    def container_data_volume(self) -> str:
        """Named Docker volume shared between the orchestrator and client containers."""
        return self.get("containers", "data_volume", default="")

    @property
    def container_host_data_path(self) -> str:
        """Host bind-mount path for /data — used instead of data_volume if set."""
        return self.get("containers", "host_data_path", default="")

    @property
    def container_gam_host_path(self) -> str:
        """Host path for the GAM binary directory (e.g. /home/user/bin/gam7)."""
        return self.get("containers", "host_gam_path", default="")


def load_config() -> Config:
    config_path = Path(
        os.environ.get("GAM_WEBUI_CONFIG", "./config.yaml")
    )
    data = _load_yaml(config_path)
    return Config(data)


# Module-level singleton — imported by other modules
cfg: Config = load_config()
