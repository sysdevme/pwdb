# Password Manager (Go) - Unified README

Default development branch: `v4`.

This repository now combines:

- Core application features from `v3`
- un1t master/un1t slave + un1t controller work from `v4`

## Security notice

This project is intended for development, lab testing, and self-hosted trusted environments.
It is not production-ready and should not be exposed directly to the public internet without additional hardening.

## What the project includes

- PostgreSQL storage
- Dockerized app + DB
- Web UI built with Bootstrap 5
- Password and secure note vaults
- Tags/groups organization
- Multi-user admin/user lifecycle
- Sharing between active users
- Server-side crypto with Argon2id + AES-GCM
- Optional distributed topology (`AS-M`/`AS-S`) via controller APIs (experimental)
- Embedded controller service source at `controller/`

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

App: `http://localhost:8080`

First setup:

- `http://localhost:8080/setup`

Login:

- `http://localhost:8080/login`

## Core features (stable app surface)

- Password and secure note CRUD
- Tags and groups with detail pages
- Tags and groups collection pages rendered as cards with `Edit` and `Remove` actions
- Dashboard shows `Tags` and `Groups` as two cards in one row
- Search filters and pagination on list pages
- Sharing items with other active users (shared items are recipient read-only)
- Internal user-to-user short messages (`Messages` page, max 300 chars)
- Shared password recipient action is `Unshare` (removes own access only; does not delete owner record)
- Password view supports inline owner updates for item name, tags, and groups (including selecting from existing tags/groups)
- Pending -> active user lifecycle on first successful login
- Timed unlock session with manual lock
- Account page for user credential updates
- Admin backup/restore and cleanup tools
- 1Password 7 `.1pif` import + import issue tracking
- Optional macOS biometric helper flow; Windows falls back to password unlock
- Admin users navigation:
  - `Admin -> Users -> Create` (dedicated page)
  - `Admin -> Users -> List` (dedicated page)
- Navbar account UX:
  - Right side shows only user email dropdown
  - Dropdown includes unlock status, Lock/Unlock action, and Logout
  - View size controls moved from navbar to Settings page
  - Tags/Groups moved to top navbar `Filter` dropdown
- Settings page:
  - Includes node role switch (`AS-M` <-> `AS-S`)
  - `AS-M` -> `AS-S` validates linked master availability and shows popup with failure reason when blocked

## Experimental: un1t master/un1t slave + un1t controller (under development)

The distributed topology is experimental.
Expect protocol/schema changes while development continues.

Current design:

- Setup mode:
  - `AS-M` (un1t master)
  - `AS-S` (un1t slave)
- un1t controller onboarding:
  - Bootstrap registers/updates controller identity
  - Unapproved controller receives pending onboarding response
  - Admin approval is required before operational token is issued
  - un1t controllers have configurable `weight` (higher weight = higher priority)
- Admin telemetry:
  - Master: controller links, health, last handshake, registry approval state
  - Slave: incoming controller events + remote master link status (reachability and link-health summary)
  - Admin cleanup for stale controllers based on inactivity threshold
- Periodic master -> slave health checks

Current protocol endpoints:

- Controller -> Master:
  - `POST /controller/pair`
  - `POST /controller/update/ack`
  - `GET /controller/controllers` returns controllers ordered by `weight DESC`
- Controller -> Slave:
  - `POST /controller/snapshot/apply`
  - `POST /controller/update/apply`
- Master -> Slave:
  - `GET /controller/health`
- Controller -> Master (status query):
  - `GET /controller/links/status`

Embedded controller status (`controller/`):

- Background worker loop with retry backoff
- Pair relay + automatic slave update apply + master ACK relay
- Local persisted sync metadata per slave (`last_synced_version`, `last_synced_event_id`, `last_sync_error`)
- Manual controller endpoints:
  - `POST /v1/slaves/sync`
  - `POST /v1/slaves/unregister`

Controller run (from this repository):

Windows (PowerShell):

```powershell
cd E:\pwdb-main\controller
go run ./cmd/controller -config configs/controller.dev.json
```

Linux/macOS (bash):

```bash
cd /opt/pwdb-main/controller
go run ./cmd/controller -config configs/controller.dev.json
```

Bootstrap controller against master:

Windows (PowerShell):

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:9091/v1/master/bootstrap" `
  -ContentType "application/json" `
  -Body (@{ master_key = "<CONTROLLER_MASTER_KEY>" } | ConvertTo-Json -Compress)
```

Linux/macOS (bash):

```bash
curl -sS -X POST "http://127.0.0.1:9091/v1/master/bootstrap" \
  -H "Content-Type: application/json" \
  -d '{"master_key":"<CONTROLLER_MASTER_KEY>"}'
```

Then list visible controllers (token rotates each call):

Windows (PowerShell):

```powershell
curl.exe -sS http://127.0.0.1:9091/v1/master/controllers
```

Linux/macOS (bash):

```bash
curl -sS http://127.0.0.1:9091/v1/master/controllers
```

## Environment

Copy `.env.example` to `.env` and adjust values.

Important variables:

- `MASTER_PASSWORD`
- `DATABASE_URL`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_DB`
- `APP_ADDR`

Controller-related variables:

- `CONTROLLER_SHARED_TOKEN`
- `CONTROLLER_MASTER_KEY`

Optional UI service restart controls:

- `UI_SERVICE_RESTART_ENABLED`
- `UI_SERVICE_RESTART_COMMAND`
- `UI_SERVICE_RESTART_ARGS`

## App version metadata

Application version metadata is stored in:

- `static/version.json`

Fields:

- `version`
- `author`
- `last_update`
- `repo_url`

The navbar brand section reads this file and shows `v<version>` near `Un1t PM`.
The backend also reads this file and exposes metadata in `Admin -> About`.

## Local dev scripts

Local helper scripts (for example under `scripts/`) may exist in your environment but are intentionally not part of the tracked repository state.
Keep/customize them per environment.

## Migrations for distributed mode

- `010_server_profile.sql`
- `011_controller_links.sql`
- `012_controller_update_events.sql`
- `013_controller_links_handshake.sql`
- `014_controller_registry.sql`
- `017_internal_messages.sql`

## Recent fixed bugs

<details>
<summary>Open fixed bugs list</summary>

- Duplicate slave rows in `Controller Links` for same endpoint re-registration.
- Missing cleanup path for existing duplicates (`Cleanup Duplicate Endpoints` action).
- Link freshness drift addressed with periodic health checks (`GET /controller/health`).
- Unapproved controllers no longer receive operational token on first bootstrap.
- Admin Users submenu flow changed to dedicated pages (removed dashboard modal race).
- Slave admin now shows remote master link status (reachable/offline + active/stale/offline counts).
- Controller registry now supports per-controller `weight` and ordering by priority.
- Added `Cleanup Stale Controllers` action in Admin (disables inactive approved controllers by age threshold).
- Restored `Unlock` action in account dropdown while already unlocked, so users can extend unlock time without waiting for expiry.

</details>

## Security limitations

- No default TLS/HTTPS termination inside app container
- No mTLS for controller endpoints yet
- Shared-token based controller auth model still in transition
- No built-in rate limiting/brute-force controls for controller APIs

If deploying beyond local lab use, place behind a hardened reverse proxy with HTTPS and apply additional auth/rate-limit controls.
