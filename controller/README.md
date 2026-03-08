# PWDB Controller

Experimental controller service for the PWDB v4 topology, now embedded in this repository under `controller/`.

## What this service does now

- Runs HTTP server on a port from config.
- Bootstraps against master using a `master_key`.
- Stores and rotates access token from master responses.
- Lists available controllers from master.
- Registers slaves only with controller IDs that are active in master list.
- Relays slave registration to master via `POST /controller/pair` before saving local state.
- Persists local runtime state (`token`, registered slaves) to JSON file.
- Runs a background sync loop (goroutine) that periodically refreshes controller list/token and re-relays pair for registered slaves.
- Uses retry backoff in worker loop and exposes last sync status in `/health`.
- Automatically sends update events to active slaves (`/controller/update/apply`) and sends ACK back to master (`/controller/update/ack`).
  - Event ID format is global-per-version: `evt-<vault_version>`.

## Config

Edit `configs/controller.dev.json`.

Important fields:

- `listen_addr`: controller API bind address
- `controller_id`: unique controller identifier
- `sync_interval_sec`: worker sync interval in seconds (default `30`)
- `master.base_url`: master PWDB URL
- `master.bootstrap_path`: endpoint for key authentication
- `master.rotate_path`: endpoint for token rotation
- `master.controllers_path`: endpoint that returns available controllers + next token
- `master.pair_path`: endpoint that registers slave link on master
- `master.update_apply_path`: path used when sending update events to each slave
- `master.update_ack_path`: endpoint on master for update ACK
- `master.shared_token`: shared token sent as `X-Controller-Token` for pair/apply/ack controller calls

## Run

```powershell
cd E:\pwdb-main\controller
go run ./cmd/controller -config configs/controller.dev.json
```

## API (controller local)

### Health

`GET /health`

### Bootstrap with master key

`POST /v1/master/bootstrap`

Body:

```json
{ "master_key": "your-master-provided-key" }
```

### Get available controllers from master (token rotates)

`GET /v1/master/controllers`

### Register slave by selected controller ID

`POST /v1/slaves/register`

Body:

```json
{
  "slave_id": "slave-1",
  "slave_url": "http://10.1.12.45:8080",
  "controller_id": "controller-01"
}
```

If `controller_id` is omitted, controller auto-selects the highest-weight active controller from master registry.

### List local registered slaves

`GET /v1/slaves`

### Unregister local slave

`POST /v1/slaves/unregister`

Body:

```json
{
  "slave_id": "slave-1"
}
```

### Trigger immediate sync

`POST /v1/slaves/sync`

Returns sync counters including `updates_sent`.

## Notes

- This is a first scaffold and is intentionally minimal.
- It assumes master endpoints return `next_token` on auth/list calls.
- Slave registration requires `master.shared_token` in config.
- No TLS/mTLS yet, no distributed coordination yet.
- Current change trigger is heuristic: controller computes a fingerprint from master controller registry state and emits a new version when fingerprint changes.
- Sync processing prioritizes slaves bound to higher-weight controllers first.
