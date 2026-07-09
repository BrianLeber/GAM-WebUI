"""
GAM WebUI client onboarding CLI.

Run from inside the container:
    docker exec -it gam-webui-app-1 python -m cli.onboard <command>

Commands:
    list                              List all registered clients
    create                            Register a new client (interactive),
                                      then optionally enroll GAM credentials
    setup-gam <client_id> <tier>      Run full GAM enrollment for a client
                                      tier = admin | helpdesk
                                      Offers to create a GCP project if
                                      client_secrets.json is missing.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend import db
from backend.config import cfg


# ── Helpers ───────────────────────────────────────────────────────────────────

def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _ask(prompt: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    raw = input(f"{prompt} {hint}: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def _gam_run(gam_path: Path, config_dir: Path, *args) -> int:
    """Run a GAM command with config_dir inline override. Returns exit code."""
    cmd = [str(gam_path), "config", "config_dir", str(config_dir), *args]
    result = subprocess.run(cmd)
    return result.returncode


def _grant_all_admins(client_id: str) -> int:
    """Grant admin access to all tool-level admins. Returns how many were granted."""
    with db._connect() as conn:
        admins = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchall()
        count = 0
        for admin in admins:
            conn.execute(
                "INSERT OR IGNORE INTO tech_client_access "
                "(user_id, client_id, access_level, granted_at, granted_by) "
                "VALUES (?, ?, 'admin', ?, NULL)",
                (admin["id"], client_id, db.now_iso()),
            )
            count += 1
    return count


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_list():
    db.init_db()
    with db._connect() as conn:
        rows = conn.execute(
            "SELECT id, name, domain, active FROM clients ORDER BY name"
        ).fetchall()
    if not rows:
        print("No clients registered yet.")
        return
    print(f"\n{'ID':<22} {'Name':<28} {'Domain':<28} Active")
    print("-" * 84)
    for r in rows:
        active = "yes" if r["active"] else "no"
        print(f"{r['id']:<22} {r['name']:<28} {r['domain']:<28} {active}")
    print()


def cmd_create():
    db.init_db()
    print("\n=== New Client Registration ===\n")

    name = input("Client name (e.g. Acme Corporation): ").strip()
    if not name:
        print("Name is required.")
        sys.exit(1)

    suggested = _slugify(name)
    raw_id = input(f"Client ID [{suggested}]: ").strip() or suggested
    client_id = re.sub(r"[^a-z0-9-]", "-", raw_id.lower()).strip("-")
    if not client_id:
        print("Client ID is required.")
        sys.exit(1)

    domain = input("Primary Google Workspace domain (e.g. acme.com): ").strip().lower()
    if not domain:
        print("Domain is required.")
        sys.exit(1)

    default_ou = input("Default suspended OU [/Suspended]: ").strip() or "/Suspended"

    # Check for duplicate
    with db._connect() as conn:
        if conn.execute("SELECT 1 FROM clients WHERE id = ?", (client_id,)).fetchone():
            print(f"\nError: client ID '{client_id}' already exists.")
            sys.exit(1)

    # Create credential directories — chmod 0o775 so the host user can write to them
    clients_root = Path(cfg.clients_root)
    admin_dir    = clients_root / client_id / "gam-config-admin"
    helpdesk_dir = clients_root / client_id / "gam-config-helpdesk"
    for d in (admin_dir, helpdesk_dir):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o775)
        tier = "admin" if "admin" in d.name else "helpdesk"
        (d / "gam.cfg").write_text(
            f"[DEFAULT]\nconfig_dir = {d}\ncache_dir = /tmp/gamcache-{client_id}-{tier}\n"
        )
    print(f"\nCreated: {admin_dir}")
    print(f"Created: {helpdesk_dir}")

    # Insert client record
    with db._connect() as conn:
        conn.execute(
            "INSERT INTO clients "
            "(id, name, domain, gam_config_admin_path, gam_config_helpdesk_path, "
            " default_terminated_ou, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                client_id,
                name,
                domain,
                f"{client_id}/gam-config-admin",
                f"{client_id}/gam-config-helpdesk",
                default_ou,
                db.now_iso(),
            ),
        )

    granted = _grant_all_admins(client_id)
    if granted:
        print(f"Granted admin access to {granted} existing admin user(s).")

    print(f"\nClient '{name}' registered as '{client_id}'.")

    if _ask("\nSet up GAM admin credentials now?"):
        cmd_setup_gam(client_id, "admin")
    else:
        print("\nRun this when ready:")
        print(f"  docker exec -it gam-webui-app-1 python -m cli.onboard setup-gam {client_id} admin")
        print()


def cmd_setup_gam(client_id: str, tier: str):
    db.init_db()

    if tier not in ("admin", "helpdesk"):
        print(f"Error: tier must be 'admin' or 'helpdesk', got '{tier}'")
        sys.exit(1)

    row = db.get_client_by_id(client_id)
    if not row:
        print(f"Error: client '{client_id}' not found. Run 'create' first.")
        sys.exit(1)

    gam_path = Path(cfg.gam_path)
    if not gam_path.exists():
        print(f"Error: GAM binary not found at {gam_path}")
        print("Make sure the GAM volume is mounted (/opt/gam7).")
        sys.exit(1)

    config_dir = Path(cfg.clients_root) / client_id / f"gam-config-{tier}"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_dir.chmod(0o775)

    # Write / refresh gam.cfg
    (config_dir / "gam.cfg").write_text(
        f"[DEFAULT]\nconfig_dir = {config_dir}\ncache_dir = /tmp/gamcache-{client_id}-{tier}\n"
    )

    print(f"\n=== GAM {tier.upper()} enrollment: {row['name']} ({client_id}) ===")
    print(f"Config directory : {config_dir}")
    print(f"GAM binary       : {gam_path}")
    print()

    secrets  = config_dir / "client_secrets.json"
    svc_acct = config_dir / "oauth2service.json"

    # ── Step 1: Google Cloud project / client_secrets.json ────────────────────
    if not secrets.exists():
        print("client_secrets.json not found.")
        print()
        if _ask("Create a new Google Cloud project now? (opens browser)"):
            print()
            print("GAM will walk you through creating a GCP project and enabling APIs.")
            print("=" * 64)
            rc = _gam_run(gam_path, config_dir, "create", "project")
            if rc != 0:
                print(f"\nGAM exited with code {rc}. Fix the error above and re-run setup-gam.")
                sys.exit(rc)
            if not secrets.exists():
                print("\nWarning: client_secrets.json still not found after 'create project'.")
                print("Check the output above for errors.")
                sys.exit(1)
            print("\nclient_secrets.json created successfully.")
        else:
            print()
            print("Copy client_secrets.json from an existing GAM setup, then re-run:")
            print(f"  docker exec -it gam-webui-app-1 python -m cli.onboard setup-gam {client_id} {tier}")
            sys.exit(0)

    # ── Step 2: OAuth user authorization ─────────────────────────────────────
    print()
    print("Step: Authorize a Workspace admin user via OAuth.")
    print("You will be shown a URL — open it in your browser, sign in as a")
    print("super admin for this Google Workspace, then paste the code back here.")
    print("=" * 64)
    print()
    rc = _gam_run(gam_path, config_dir, "oauth", "create")
    if rc != 0:
        print(f"\nGAM exited with code {rc}. Check the output above.")
        sys.exit(rc)
    if (config_dir / "oauth2.txt").exists():
        print(f"\nOAuth credentials saved to {config_dir}/oauth2.txt")

    # ── Step 3: Service account (forwarding / delegation) ────────────────────
    print()
    if not svc_acct.exists():
        if _ask("Create a service account for forwarding/delegation support? (recommended)"):
            print()
            print("GAM will create a service account and show you the client ID.")
            print("After this step, go to your Google Admin Console:")
            print("  Security → API Controls → Domain-wide delegation")
            print("  Add the service account client ID with the required scopes.")
            print("=" * 64)
            print()
            rc = _gam_run(gam_path, config_dir, "create", "service-account")
            if rc == 0 and svc_acct.exists():
                print(f"\nService account saved to {config_dir}/oauth2service.json")
                _print_dwd_reminder(client_id, tier, config_dir)
            else:
                print(f"\nGAM exited with code {rc}. Service account setup may be incomplete.")
        else:
            print("Skipped. Forwarding and delegation will not work without a service account.")
            print(f"Run later:  docker exec -it gam-webui-app-1 /opt/gam7/gam config config_dir {config_dir} create service-account")
    else:
        print(f"Service account already present: {svc_acct}")

    print(f"\nGAM {tier} enrollment complete for '{row['name']}'.")
    print("Refresh the dashboard to start using this client.\n")


def _print_dwd_reminder(client_id: str, tier: str, config_dir: Path):
    """Print the domain-wide delegation reminder."""
    svc_file = config_dir / "oauth2service.json"
    client_id_val = ""
    if svc_file.exists():
        import json
        try:
            data = json.loads(svc_file.read_text())
            client_id_val = data.get("client_id", "")
        except Exception:
            pass

    print()
    print("─" * 64)
    print("ACTION REQUIRED — Domain-Wide Delegation")
    print("─" * 64)
    print("In the Google Admin Console for this Workspace:")
    print("  Admin Console → Security → API Controls → Domain-wide delegation")
    print("  → Add new → paste the client ID below")
    if client_id_val:
        print(f"\n  Client ID: {client_id_val}")
    print()
    print("  Required OAuth scopes (paste as comma-separated list):")
    scopes = [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
    ]
    print("  " + ",".join(scopes))
    print("─" * 64)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    cmd = args[0]
    if cmd == "list":
        cmd_list()
    elif cmd == "create":
        cmd_create()
    elif cmd == "setup-gam":
        if len(args) < 3:
            print("Usage: setup-gam <client_id> <admin|helpdesk>")
            sys.exit(1)
        cmd_setup_gam(args[1], args[2])
    else:
        print(f"Unknown command: {cmd}")
        print("Commands: list, create, setup-gam")
        sys.exit(1)


if __name__ == "__main__":
    main()
