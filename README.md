# Password Manager (Go)

## Security Notice

This project is a prototype and is intended for local development and experimentation only.
It is not production-ready and should not be exposed directly to the public internet without additional security hardening.

This is a starter scaffold for a password manager with:

- PostgreSQL storage
- Dockerized app + DB
- Web UI built with Bootstrap 5 (no custom CSS)
- Data types: login/password, tagged password entries, secure notes
- Multi-user admin setup with pending/active user lifecycle
- Item sharing for passwords and secure notes between active users
- Server-side encryption with Argon2id + AES-GCM (key derived from `MASTER_PASSWORD`)

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

App: https://localhost:8443  
DB: localhost:5432 (user: `pm`, password: `pm`, db: `pm`)

## Certificates

Place TLS files in the project `certs/` folder (this folder is gitignored):
- certificate: `certs/certificate` (or `certs/certificate.pem` / `certs/certificate.crt`)
- private key: `certs/key` (or `certs/private`, `certs/key.pem`, `certs/private.key`, `certs/private.pem`)

If needed, override certificate paths in `.env`:
- `TLS_CERT_FILE` (or `CERT_FILE`)
- `TLS_KEY_FILE` (or `KEY_FILE`)

## Multi-user setup

On first run, open:
```
https://localhost:8443/setup
```

Create the initial admin user. After that, log in at:
```
https://localhost:8443/login
```

Admin can create additional users in the Admin page.
Newly created users start in `pending` status and automatically become `active` after their first successful login.

## Current features

- Password and secure note CRUD
- Tags and groups with detail pages showing where each tag/group is used
- Item sharing with other active users (shared items are read-only for recipients)
- Field-based search on list pages (selector + query input)
- Pagination on list pages (10 records per page)
- Bordered table design for passwords, notes, tags, and groups
- Shared-item visual marker with deterministic pixel avatar
- Automatic list hiding on unlock session expiration until re-unlock
- Navbar view-size control (100% / 90% / 80% / 70% / 60% / 50%)
- Settings page for per-user preferences (records/page, unlock duration, firewall placeholder, API key)
- Tags and groups moved under Settings navigation links
- Per-user login password and master password
- Account page for users to update their own login and master passwords
- Admin backup/restore and credential reset tools
- Admin cleanup tools for tags/groups (record-level and global clear)
- 1Password 7 `.1pif` import with import issue tracking
- Timed unlock session with manual lock
- macOS biometric helper integration; Windows skips biometric probing and falls back directly to the password prompt

## Release Notes

<details>
<summary>v3.0.4</summary>

- Added Settings page with:
  - records-per-page preference used by list pagination
  - configurable unlock session duration (minutes)
  - firewall enable/disable placeholder flag
  - API key field
- Moved Tags/Groups top-menu access into Settings.
- Added Admin cleanup operations:
  - clear tags for a specific record UUID
  - clear groups for a specific record UUID
  - clear all tags table data (with link cleanup)
  - clear all groups table data (with link cleanup)
- Unlock endpoint now respects configured unlock session minutes.

</details>

<details>
<summary>v3.0.2</summary>

- Redesigned list pages to bordered admin-style tables.
- Added field-based search controls for passwords, notes, tags, and groups.
- Added 10-items-per-page pagination with filter-preserving next/previous links.
- Added shared-item indicator column with deterministic pixel avatars.
- Hid records immediately on unlock-session expiration and on locked page render.
- Added navbar site-width control for quick resize presets.
- Added `make.bat` for Windows users with Makefile-equivalent core targets.

</details>

<details>
<summary>v3.0.1</summary>

- Added user lifecycle status (`pending` to `active` on first successful login).
- Added sharing for passwords and secure notes between active users.
- Added account page for self-service login/master password updates.
- Added tag and group detail pages listing the items that use them.
- Windows clients now skip biometric helper checks and go straight to password unlock.
- Added schema migration `008_user_status_and_sharing.sql`.

</details>

<details>
<summary>v2.1.2</summary>

- Centralized SQL statements in `internal/db/queries.go`.
- Moved parameterless and parameterized DB queries out of inline method bodies.
- Updated `internal/db/db.go` to reuse named query constants across store methods.
- Refactor only: no functional or deployment changes required.

</details>

<details>
<summary>v2.1.1</summary>

- Centralized unlock flow with 5‑minute session, countdown, and manual lock button.
- macOS TouchID helper with local server integration for unlock.
- Import history and import issues tracking.
- Raw 1PIF storage with “More Fields” viewer and concealed field toggles.
- Admin backup/restore (JSON) page.
- Static assets support for custom JS/CSS.
- Password generator in the password form.
- Multi-user authentication with per-user data isolation.
- Admin setup/login flow and user creation.
- Separate login and master passwords per user, with admin reset tools.
- Tags and groups listing with counts per user.
- Password form suggests existing tags/groups with custom entry support.
- Password view page can generate and update the password in-place (with confirmation).
- Password view masks secrets with per-field eye toggle and click-to-copy.
- Import history is scoped per user.
- Redesigned login page layout with Restore modal.
- Login/setup pages use a full-height layout without the main navbar.

</details>

## Environment configuration

Credentials and runtime settings are loaded from `.env` (not committed).  
Copy `.env.example` and edit:

```bash
cp .env.example .env
```

Key settings:
- `MASTER_PASSWORD` (required, used for server-side encryption/decryption)
- `DATABASE_URL`
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- `APP_ADDR`
- `TLS_CERT_FILE`, `TLS_KEY_FILE` (optional overrides for cert/key paths)

## Using the Makefile

The repository includes a `Makefile` so you can run common tasks with short commands.

### Common targets

```bash
make build          # Build server binary to ./bin/server
make run            # Run server locally with go run
make test           # Run Go tests
make docker-build   # Build Docker image password-manager-go:local
make docker-up      # Start app + dependencies with Docker Compose
make docker-down    # Stop Docker Compose services
make restart        # Recreate Docker Compose services
```

### Windows helper

For Windows PowerShell/CMD without GNU Make, use:

```bat
.\make.bat build
.\make.bat docker-up
.\make.bat restart
```

### Docker Compose file selection

`make docker-up`, `make docker-down`, and `make restart` use `COMPOSE_FILE` from the Makefile.

- Default in this repository: `docker-compose.yml`

If you want to use a different Compose file, pass it explicitly:

```bash
make docker-up COMPOSE_FILE=your-compose-file.yml
```

### macOS biometric helper targets

```bash
make macos-helper    # Build ./bin/macos-unlock
make restart-helper  # Restart helper server in background
make restart-all     # Restart Docker services + helper server
```

## Notes

- Import from 1Password 7 `.1pif` is included with secure notes and extra fields parsing.
- During import from 1Password (tested with 1Password 7), the raw JSON string is also stored temporarily.
- CLI terminal UI with three panes is stubbed in `cmd/cli`; we can build it after the web backend stabilizes.


## Security Limitations

- The application now starts with HTTPS and requires certificate/key files.
- Server-side encryption relies on a single `MASTER_PASSWORD` from the environment (not per-user).
- No built-in rate limiting or brute-force protection is implemented.
- This project should still be placed behind a hardened reverse proxy for production deployments.

## macOS TouchID/FaceID helper (CLI)

This is optional and works with the current `/auth/biometric-unlock` endpoint.
The biometric helper is intended for macOS local use. On Windows, the UI falls back directly to the master password prompt.

Build:
```bash
mkdir -p bin
swiftc -framework LocalAuthentication -framework Security -o bin/macos-unlock ./macos-unlock/main.swift
```

Store master password in Keychain (one-time, per user):
```bash
security add-generic-password -a default -s com.password-manager-go.master -w "YOUR_MASTER_PASSWORD" -T ""
```

Run (one-shot, prints a token):
```bash
./bin/macos-unlock
```

Run helper server for the web UI button (per user):
```bash
export PM_SERVER_URL="https://127.0.0.1:8443/auth/biometric-token"
export PM_USER_EMAIL="your-user@example.com"
./bin/macos-unlock --server
```

This will prompt TouchID/FaceID, read the master password from Keychain, and return a short-lived token to the web UI.


## Production Considerations

If adapting this project for production use, you should:

- Enforce TLS policy and certificate lifecycle via reverse proxy (Nginx, Traefik, etc.)
- Use per-user encryption keys and a proper key management scheme
- Add rate limiting and authentication hardening
- Review and audit cryptographic implementation

## Disclaimer

This software is provided as-is without warranty of any kind.
The author is not responsible for data loss, security breaches, or misuse of this software.
