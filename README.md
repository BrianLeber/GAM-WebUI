# GAM WebUI

A multi-tenant web console for managing Google Workspace domains via
[GAMADV-XTD3](https://github.com/taers232c/GAMADV-XTD3) (GAM 7). Built for MSPs:
one deployment, many client domains, with per-technician access control and a
full audit trail — so day-to-day Workspace tasks don't require handing every
tech raw GAM on a shell.

**Status:** v0.1.0 — early, functional, in production use for a small number of tenants.

## What it does

- **Multi-tenant dashboard** — each Google Workspace client is enrolled once and
  appears as a card; techs only see clients they've been granted access to.
- **User operations** — list/search users and OUs, suspend/unsuspend, move OU,
  reset passwords (cryptographically random, never displayed or logged).
- **Gmail operations** — set/remove forwarding, add/remove delegates,
  set/clear vacation responders.
- **Offboarding** — a one-click termination flow (deprovision, reset password,
  forwarding/delegation handoff) that writes a full pre-termination snapshot to
  disk before touching anything.
- **Scheduled actions** — queue operations (e.g. "remove this forward in 30 days")
  for a background scheduler to execute.
- **Multi-user with roles** — `admin` and `tech` roles; admins manage users and
  per-client access grants from the UI. Local email/password auth (bcrypt);
  Microsoft and Google SSO are scaffolded but not yet active.
- **Two credential tiers per client** — full-scope `admin` and reduced-scope
  `helpdesk` GAM credentials, selected automatically by the tech's access level.
- **Audit log** — every GAM command is logged per-client (append-only JSONL)
  with the acting technician's identity.

## Architecture

```
┌─────────────────────────┐
│  app container          │        ┌──────────────────────┐
│  FastAPI + SQLite       │─exec──▶│ gam-client-{id}      │  one per client,
│  plain HTML/JS frontend │ (SDK)  │ sleep infinity + GAM │  started on demand
└───────────┬─────────────┘        └──────────────────────┘
            │ /var/run/docker.sock
```

- **FastAPI + SQLite** (stdlib `sqlite3`, no ORM) with a plain HTML/JS frontend —
  no build step, no framework.
- **One Docker container per client** (`gam-client-{client_id}`), managed via the
  Docker Python SDK over the socket. Containers idle with `sleep infinity`; GAM
  commands run through `exec`. An LRU cap plus an idle reaper keep the container
  count bounded.
- **GAM binary mounted read-only from the host** — update GAM once on the host and
  every client picks it up; no image rebuilds.
- **All mutable state under one `/data` volume** (config, DB, logs, per-client
  credentials) so backup and migration are a single `tar`.

### GAM quirks this codebase works around

- `GAMCONFIGDIR` is unreliable in GAM 7 (it's ignored once `/root/.gam/gam.cfg`
  exists), so every command is prefixed inline: `gam config config_dir <path> …`.
- `gam show delegates csv` produces no output; `gam print delegates` is used
  instead (delegate address is column 2).
- The client data mount is read-write, not read-only, because GAM refreshes
  OAuth tokens in `oauth2.txt` in place.

## Quick start

Requirements: Docker with compose, a GAM 7 / GAMADV-XTD3 install on the host,
and per-client GAM credentials (see [Onboarding a client](#onboarding-a-client)).

```bash
# 1. Build the client container image
docker build -f Dockerfile.client -t gam-client .

# 2. Configure
cp config.example.yaml data/config.yaml
$EDITOR data/config.yaml     # set secret_key, gam paths, auth settings

# 3. Run
docker compose up -d
```

On first launch, visit `/setup` to create the initial admin account. Put a
TLS-terminating reverse proxy (nginx, Caddy, Cloudflare Tunnel, Tailscale) in
front for anything beyond a private LAN, and set `session.secure_cookies: true`.

## Onboarding a client

Each client needs a directory under `/data/clients/{client_id}/` containing one
or two GAM credential tiers:

```
clients/{client_id}/
  gam-config-admin/        # full scope
    client_secrets.json
    oauth2.txt
    oauth2service.json     # service account — required for forwarding/delegation
  gam-config-helpdesk/     # reduced scope (optional)
    ...
```

`cli/onboard.py` provides an interactive registration + enrollment flow: it
walks the GAM OAuth setup in a sandboxed directory, verifies the credentials,
and registers the client in the database. `oauth2service.json` (domain-wide
delegation) is what enables the Gmail forwarding/delegate features.

## Configuration

All app-level settings live in `data/config.yaml` — see
[`config.example.yaml`](config.example.yaml), which documents every option
(auth modes, session lifetimes, container caps and idle timeouts, scheduler
interval). Per-client settings live in the database and are managed through
the UI or CLI. Any option can be overridden by environment variable using
`SECTION__KEY` naming, e.g. `APP__SECRET_KEY`.

## Security notes

- Credentials, database, and logs live only under `data/` — the entire
  directory is gitignored, as are `*.json`, `oauth2.txt`, and key material,
  so client secrets can't be committed by accident.
- The app never writes GAM credentials; it only reads what onboarding placed.
- `auth.mode: none` disables login entirely and exists for local development
  only. Never deploy with it.
- The app container has the Docker socket mounted, which is root-equivalent on
  the host — treat the host as part of the trust boundary and don't expose the
  app directly to the internet.

## Roadmap

- Microsoft / Google SSO for staff login
- Validated GAM CLI passthrough terminal (admin-only)
- Local-LLM natural-language command composition (suggest-and-review, never auto-execute)

## License

No license yet — all rights reserved. Open an issue if you want to use this.
