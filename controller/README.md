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
- Exports master snapshot data and applies it to active slaves (`/controller/snapshot/apply`), then sends ACK back to master (`/controller/update/ack`).
- Prioritizes slaves bound to higher-weight controllers first.

## Config

Edit `configs/controller.dev.json`.

Important fields:

- `listen_addr`: controller API bind address
- `controller_id`: unique controller identifier
- `sync_interval_sec`: worker sync interval in seconds (default `30`)
- `master.base_url`: master PWDB URL
- `master.port`: optional override for master access port (if set, replaces port from `master.base_url`)
- `master.master_key`: optional bootstrap key used for auto-bootstrap when token is empty
- `slave.default_port`: optional default port used when `slave_url` is registered without explicit port
- `master.bootstrap_path`: endpoint for key authentication
- `master.rotate_path`: endpoint for token rotation
- `master.controllers_path`: endpoint that returns available controllers + next token
- `master.pair_path`: endpoint that registers slave link on master
- `master.snapshot_export_path`: endpoint used to export snapshot data from master
- `master.snapshot_apply_path`: path used when sending snapshot data to each slave
- `master.update_ack_path`: endpoint on master for update ACK
- `master.shared_token`: local fallback only; prefer `CONTROLLER_SHARED_TOKEN` from environment for pair/snapshot/ack controller calls

## Run

Windows (PowerShell):

```powershell
cd E:\pwdb-main\controller
go run ./cmd/controller -config configs/controller.dev.json
```

Linux/macOS (bash):

```bash
cd /opt/pwdb-main/controller
CONTROLLER_SHARED_TOKEN="<CONTROLLER_SHARED_TOKEN>" \
CONTROLLER_MASTER_KEY="<CONTROLLER_MASTER_KEY>" \
go run ./cmd/controller -config configs/controller.dev.json
```

Environment overrides:

- `CONTROLLER_SHARED_TOKEN` overrides `master.shared_token`
- `CONTROLLER_MASTER_KEY` overrides `master.master_key`
- If the shared token is missing or still a placeholder, controller startup fails fast with a clear error

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
  "slave_url": "http://10.1.12.45",
  "controller_id": "controller-01"
}
```

If `slave.default_port` is set to `8080`, the example above is normalized to `http://10.1.12.45:8080`.

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

## Auto-bootstrap behavior

- If `master.master_key` is set and controller token is empty, worker auto-calls bootstrap.
- If master returns `pending_approval`, controller waits and retries automatically on worker interval.
- After admin approval on master, a later auto-bootstrap obtains token and sync starts without manual curl.

## Notes

- This is a first scaffold and is intentionally minimal.
- It assumes master endpoints return `next_token` on auth/list calls.
- Slave registration and sync require a valid controller shared token from environment or another local-only secret source.
- No TLS/mTLS yet, no distributed coordination yet.
- Current sync path sends snapshot data, not true per-record delta events.
- Deletes and full convergence cleanup are still not implemented.
