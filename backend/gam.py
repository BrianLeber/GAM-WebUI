"""
GAM subprocess wrapper — docker exec edition.

Every GAM operation runs via exec_run against the client container.
The container is started/stopped by container_manager.py.  GamClient is
instantiated per-request and carries only the client_id and credential tier;
the container is assumed to be running (ensure_running() is called upstream).

Credential tiers:
  admin    — gam-config-admin/   (full scope)
  helpdesk — gam-config-helpdesk/ (reduced scope)

Container path for credentials depends on the volume strategy:
  - host_data_path (bind mount): /client-data/gam-config-{tier}/
  - data_volume (named volume):  /data/clients/{client_id}/gam-config-{tier}/
"""
import secrets
import string
from dataclasses import dataclass
from pathlib import Path

from .config import cfg
from .container_manager import container_name as get_container_name, exec_in_container


@dataclass
class GamClient:
    """
    Bound GAM executor for a specific client and credential tier.
    Instantiate via GamClient.for_access_level() in request handlers.
    """
    client_id:      str
    tier:           str   # "admin" | "helpdesk"
    container_name: str
    gam_path:       str = ""

    def __post_init__(self):
        if not self.gam_path:
            self.gam_path = cfg.gam_path

    @classmethod
    def for_access_level(cls, client_id: str, access_level: str) -> "GamClient":
        tier = "admin" if access_level == "admin" else "helpdesk"
        return cls(
            client_id=client_id,
            tier=tier,
            container_name=get_container_name(client_id),
        )

    # ── Internal runner ────────────────────────────────────────────────────

    def _config_dir(self) -> str:
        if cfg.container_host_data_path:
            # Bind-mount: only this client's dir is mounted at /client-data
            return f"/client-data/gam-config-{self.tier}"
        # Named volume: full /data tree is mounted
        return str(Path(cfg.clients_root) / self.client_id / f"gam-config-{self.tier}")

    def _gam(self, *args) -> list[str]:
        """Build a GAM command with inline config_dir override."""
        return [self.gam_path, "config", "config_dir", self._config_dir(), *args]

    def _run(self, *args, timeout: int = 60) -> tuple[bool, str]:
        exit_code, stdout, stderr = exec_in_container(self.client_id, self._gam(*args))
        output = (stdout + "\n" + stderr).strip()
        return exit_code == 0, output

    # ── User list ──────────────────────────────────────────────────────────

    def list_users(self) -> tuple[bool, list[str]]:
        exit_code, stdout, _ = exec_in_container(
            self.client_id,
            self._gam("print", "users", "fields", "primaryemail"),
        )
        emails = []
        for line in stdout.splitlines():
            line = line.strip()
            if "@" in line and not line.lower().startswith("primaryemail"):
                email = line.split(",")[0].strip().lower()
                if "@" in email:
                    emails.append(email)
        return exit_code == 0, sorted(emails)

    # ── OU list ────────────────────────────────────────────────────────────

    def list_ous(self) -> tuple[bool, list[str]]:
        exit_code, stdout, _ = exec_in_container(
            self.client_id,
            self._gam("print", "ous", "fields", "orgunitpath"),
        )
        ous = []
        for line in stdout.splitlines():
            path = line.split(",")[0].strip()
            if path.startswith("/"):
                ous.append(path)
        return exit_code == 0, sorted(ous)

    # ── User status ────────────────────────────────────────────────────────

    def get_user_status(self, user: str) -> tuple[bool, dict]:
        ok, out = self._run("info", "user", user)
        if not ok:
            return False, {"error": out}
        data: dict = {"raw": out}
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("Full Name:"):
                data["fullName"] = s.split(":", 1)[1].strip()
            elif s.startswith("Account Suspended:"):
                data["suspended"] = s.split(":", 1)[1].strip() == "True"
            elif s.startswith("Is Archived:"):
                data["archived"] = s.split(":", 1)[1].strip() == "True"
            elif s.startswith("Google Org Unit Path:"):
                data["orgUnit"] = s.split(":", 1)[1].strip()
            elif s.startswith("2-step enrolled:"):
                data["twosvEnrolled"] = s.split(":", 1)[1].strip() == "True"
            elif s.startswith("2-step enforced:"):
                data["twosvEnforced"] = s.split(":", 1)[1].strip() == "True"
            elif s.startswith("Last login time:"):
                data["lastLogin"] = s.split(":", 1)[1].strip()
            elif s.startswith("Recovery Email:"):
                data["recoveryEmail"] = s.split(":", 1)[1].strip()
            elif s.startswith("Recovery Phone:"):
                data["recoveryPhone"] = s.split(":", 1)[1].strip()
            elif s.startswith("Google Unique ID:"):
                data["googleId"] = s.split(":", 1)[1].strip()
        return True, data

    # ── Forwarding ─────────────────────────────────────────────────────────

    def get_forward_status(self, user: str) -> tuple[bool, dict]:
        ok, out = self._run("user", user, "show", "forward")
        result: dict = {"enabled": False, "address": None, "raw": out}
        for line in out.splitlines():
            if "Forward Enabled: True" in line:
                result["enabled"] = True
            if "Forwarding Address:" in line:
                addr = line.split("Forwarding Address:")[1].split(",")[0].strip()
                result["address"] = addr
        return ok, result

    def enable_forwarding(self, user: str, forward_to: str) -> tuple[bool, str]:
        self._run("user", user, "add", "forwardingaddress", forward_to)
        return self._run("user", user, "forward", "true", "keep", forward_to)

    def disable_forwarding(self, user: str, forward_to: str) -> tuple[bool, str]:
        ok1, out1 = self._run("user", user, "forward", "false")
        ok2, out2 = self._run("user", user, "delete", "forwardingaddress", forward_to)
        return (ok1 or ok2), (out1 + "\n" + out2).strip()

    # ── Delegation ─────────────────────────────────────────────────────────

    def get_delegates(self, user: str) -> tuple[bool, list[str]]:
        ok, out = self._run("user", user, "print", "delegates")
        delegates = []
        for line in out.splitlines():
            parts = line.split(",")
            # CSV format: User,delegateAddress,delegationStatus
            if len(parts) >= 2 and "@" in parts[1]:
                delegates.append(parts[1].strip().lower())
        return ok, delegates

    def add_delegate(self, user: str, delegate: str) -> tuple[bool, str]:
        return self._run("user", user, "add", "delegate", delegate)

    def remove_delegate(self, user: str, delegate: str) -> tuple[bool, str]:
        return self._run("user", user, "delete", "delegate", delegate)

    # ── Vacation / OOO ────────────────────────────────────────────────────────

    def get_vacation(self, user: str) -> tuple[bool, dict]:
        ok, out = self._run("user", user, "show", "vacation")
        result: dict = {"enabled": False, "subject": None, "message": None,
                        "startDate": None, "endDate": None, "raw": out}
        for line in out.splitlines():
            s   = line.strip()
            low = s.lower()
            if "enabled: true" in low:
                result["enabled"] = True
            elif ("vacation subject:" in low or "autoreply subject:" in low) and result["subject"] is None:
                result["subject"] = s.split(":", 1)[1].strip()
            elif ("vacation message:" in low or "autoreply message:" in low) and result["message"] is None:
                result["message"] = s.split(":", 1)[1].strip()
            elif ("vacation start date:" in low or "autoreply start date:" in low or "start date:" in low) and result["startDate"] is None:
                val = s.split(":", 1)[1].strip()
                if val:
                    result["startDate"] = val
            elif ("vacation end date:" in low or "autoreply end date:" in low or "end date:" in low) and result["endDate"] is None:
                val = s.split(":", 1)[1].strip()
                if val:
                    result["endDate"] = val
        return ok, result

    def set_vacation(self, user: str, subject: str, message: str, end_date: str | None = None) -> tuple[bool, str]:
        args = ["user", user, "vacation", "on", "subject", subject, "message", message]
        if end_date:
            args += ["enddate", end_date]
        return self._run(*args)

    def disable_vacation(self, user: str) -> tuple[bool, str]:
        return self._run("user", user, "vacation", "off")

    # ── OU ─────────────────────────────────────────────────────────────────

    def move_user_ou(self, user: str, ou: str) -> tuple[bool, str]:
        return self._run("update", "user", user, "org", ou)

    # ── Account status ─────────────────────────────────────────────────────

    def suspend_user(self, user: str) -> tuple[bool, str]:
        return self._run("update", "user", user, "suspended", "on")

    def unsuspend_user(self, user: str) -> tuple[bool, str]:
        return self._run("update", "user", user, "suspended", "off")

    # ── Recovery & password ────────────────────────────────────────────────

    def remove_recovery_methods(self, user: str) -> tuple[bool, str]:
        return self._run("update", "user", user, "recoveryemail", "", "recoveryphone", "")

    def reset_password_random(self, user: str) -> tuple[bool, str]:
        """
        Set a cryptographically random 24-char password and discard it.
        The password is intentionally never logged or returned.
        """
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        required = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+"),
        ]
        rest = [secrets.choice(alphabet) for _ in range(20)]
        pool = required + rest
        secrets.SystemRandom().shuffle(pool)
        pw = "".join(pool)
        return self._run("update", "user", user, "password", pw)

    # ── Termination ────────────────────────────────────────────────────────

    def terminate_user(
        self,
        user: str,
        target_ou: str,
        forward_to: str | None = None,
        delegate_to: str | None = None,
    ) -> dict:
        """
        Offboard a user while keeping the mailbox functional as a mail conduit.

        Sequence:
          1. Suspend          — kills active sessions immediately
          2. Remove recovery  — eliminates self-service recovery paths
          3. Reset password   — sets an unknown random password (intentionally lost)
          4. Move OU          — repositions in directory
          5. Forward          — optional: set up mail forwarding
          6. Delegate         — optional: grant mailbox access to another user
          7. Unsuspend        — restores mail flow; account is live but inaccessible

        End state: account exists, receives and forwards mail, but former user
        has no way back in.
        """
        results = {}

        ok, out = self.suspend_user(user)
        results["suspend"] = {"ok": ok, "out": out}

        ok, out = self.remove_recovery_methods(user)
        results["removeRecovery"] = {"ok": ok, "out": out}

        ok, out = self.reset_password_random(user)
        results["resetPassword"] = {"ok": ok, "out": out}

        ok, out = self.move_user_ou(user, target_ou)
        results["moveOU"] = {"ok": ok, "out": out}

        if forward_to:
            self._run("user", user, "add", "forwardingaddress", forward_to)
            ok, out = self._run("user", user, "forward", "true", "keep", forward_to)
            results["forwarding"] = {"ok": ok, "out": out, "to": forward_to}

        if delegate_to:
            ok, out = self.add_delegate(user, delegate_to)
            results["delegate"] = {"ok": ok, "out": out, "to": delegate_to}

        ok, out = self.unsuspend_user(user)
        results["unsuspend"] = {"ok": ok, "out": out}

        return results
