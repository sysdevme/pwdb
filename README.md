# PWDB Unified Branch (v3 + v4)

This branch combines the `v3` user-facing functionality and the `v4` master/slave + controller work.

## Branch status

- Base: unified development on top of `v4`
- Includes: `v3` UI/UX and admin refinements
- Target: one active branch instead of parallel `v3`/`v4` drift

## Experimental section: master/slave + controller (in development)

The distributed topology is still under active development and should be treated as experimental.

- Server modes:
  - `AS-M` (master)
  - `AS-S` (slave)
- Controller registry onboarding:
  - bootstrap registers controller identity
  - unapproved controllers receive pending onboarding response
  - admin approval required for operational token
- Master/slave telemetry in Admin:
  - controller links + health + handshake timestamps
  - controller registry approval state
  - incoming controller events on slave
- Current transport/auth model is development-oriented (`HTTP + JSON`, shared token + master key).

Do not treat this topology as production-ready yet.

## Core application features

- Password and secure note CRUD
- Tags/groups management and detail views
- Sharing with other active users
- Search + pagination on list pages
- Timed unlock sessions + manual lock
- Per-user settings and account credential updates
- Admin backup/restore and cleanup tools
- Admin Users navigation:
  - `Admin -> Users -> Create` (dedicated page)
  - `Admin -> Users -> List` (dedicated page)

## Environment

Copy `.env.example` to `.env`.

Important variables for controller flows:

- `CONTROLLER_SHARED_TOKEN`
- `CONTROLLER_MASTER_KEY`

Optional admin service restart variables:

- `UI_SERVICE_RESTART_ENABLED`
- `UI_SERVICE_RESTART_COMMAND`
- `UI_SERVICE_RESTART_ARGS`

## Run

```powershell
cd E:\pwdb-main
docker compose up --build -d
```

Setup URL:

- `http://<host>:8080/setup`

## Security notice

This project contains experimental controller/distributed capabilities.
Use in trusted environments only; avoid public exposure until protocol hardening is complete.

## Fixed bugs (recent)

<details>
<summary>Open fixed bugs list</summary>

- Fixed duplicate slave rows in master `Controller Links` for same endpoint re-registration.
- Added admin cleanup action: `Cleanup Duplicate Endpoints`.
- Added periodic master-to-slave health checks (`GET /controller/health`).
- Enforced onboarding approval before issuing operational controller token.
- Reworked Admin Users submenu to open dedicated pages (no dashboard modal race).

</details>
