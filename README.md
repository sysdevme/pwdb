# PWDB v4 (Master/Slave + Controller Draft)

This README is specific to the `v4` branch.
It documents the current development topology and the controller integration state.

## EXPERIMENTAL STATUS (READ FIRST)

This branch is **experimental and unstable**.

- APIs, schema, and behavior can change without backward compatibility.
- Data formats and replication behavior are not finalized.
- Failures, edge-case bugs, and manual recovery may be required.
- Use for testing/lab only, not production workloads.

## What v4 adds

- Server bootstrap mode during setup:
  - `AS-M` (master)
  - `AS-S` (slave)
- Server profile persistence (`server_profile`)
- Controller HTTP endpoints (dev mode over `http`)
- Admin controller visibility:
  - Master: controller links + health + last handshake + registry approval state
  - Slave: incoming controller update events

## Topology (development)

- `pwdb-main` can run as master or slave
- `pwdb-controller` is the relay/orchestrator
- Communication is currently `HTTP + JSON`
- Legacy access control for relay endpoints uses `X-Controller-Token`
- Controller registry onboarding uses `CONTROLLER_MASTER_KEY` + rotating bearer token

Logical flow:

1. Slave is installed in `AS-S` and linked to master URL.
2. Controller calls `POST /controller/pair` on master.
3. Controller calls snapshot/update apply endpoints on slave.
4. Controller calls update ACK endpoint on master.
5. Master runs periodic health checks to linked slaves (`GET /controller/health`).
6. Admin pages show link/event telemetry.

## Current protocol surface

### Controller -> Master

- `POST /controller/pair`
- `POST /controller/update/ack`

### Controller -> Slave

- `POST /controller/snapshot/apply`
- `POST /controller/update/apply`

### Master -> Slave

- `GET /controller/health`

## Environment

Copy `.env.example` to `.env` and set values.

Required for controller API usage:

- `CONTROLLER_SHARED_TOKEN`
- `CONTROLLER_MASTER_KEY`

`CONTROLLER_SHARED_TOKEN` is still required for legacy `/controller/*` relay endpoints.
`CONTROLLER_MASTER_KEY` is required for `/controller/auth/bootstrap`.

## Setup

```powershell
cd E:\pwdb-main
docker compose up --build -d
```

Open first-run setup:

- `http://<host>:8080/setup`

During setup choose:

- `AS-M` for master (authoritative)
- `AS-S` for slave (requires linked master URL)

## Dev test scripts

From `E:\pwdb-main`:

- Pair slave on master:
  - `scripts\test-auth.bat`
- Send ACK to master:
  - `scripts\test-ack.bat`

These scripts use `curl.exe` and can be run from PowerShell.

## Admin visibility

### On master (`AS-M`)

Admin page shows:

- Slave server ID
- Slave endpoint
- Link status
- Health (`active`, `stale`, `offline`)
- Last handshake timestamp
- Controller registry list with `Approved` / `Non-approved` state
- Approve / Non-approve actions for each controller

Health thresholds:

- `active`: handshake <= 90s
- `stale`: handshake > 90s and <= 5m
- `offline`: handshake > 5m (or non-active status)

### On slave (`AS-S`)

Admin page shows incoming controller events:

- Event ID
- Master ID
- Vault version
- Event status
- Received time

## Migrations added in v4

- `010_server_profile.sql`
- `011_controller_links.sql`
- `012_controller_update_events.sql`
- `013_controller_links_handshake.sql`
- `014_controller_registry.sql`

## Implemented vs pending

Implemented:

- Mode bootstrap and persistence
- Pair + snapshot/apply + update/apply + ack endpoints
- Token-based controller auth
- Admin telemetry for master/slave controller state
- Periodic master-to-slave health checks for linked controllers
- Registry onboarding flow:
  - Bootstrap registers controller identity
  - Unapproved controllers receive pending onboarding response (no operational token)
  - Admin approval required before bootstrap returns usable token

Pending:

- Real controller worker/orchestration loop
- Automatic master-change detection and fanout to slaves
- End-to-end payload signature verification
- Production transport hardening (`https`/mTLS)

## Security notice

This is **experimental, unstable, development-stage software**.
Do not expose directly to the public internet.
Do not treat this branch as production-safe.

Current limitations:

- Controller auth is shared-token based (no mTLS yet)
- Default local/development deployment may run over plain HTTP
- No rate-limiting/brute-force controls for controller endpoints yet

## Branch and release context

- Branch: `v4`
- Latest pushed work includes master/slave topology draft and controller telemetry UI.
