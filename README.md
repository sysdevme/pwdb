# Password Manager (Go)

## Security Notice

This project is a prototype and is intended for local development and experimentation only.
It is not production-ready and should not be exposed directly to the public internet without additional security hardening.

This is a starter scaffold for a password manager with:

- PostgreSQL storage
- Dockerized app + DB
- Web UI built with Bootstrap 5 (no custom CSS)
- Data types: login/password, tagged password entries, secure notes
- Server-side encryption with Argon2id + AES-GCM (key derived from `MASTER_PASSWORD`)

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

App: http://localhost:8080  
DB: localhost:5432 (user: `pm`, password: `pm`, db: `pm`)

## Multi-user setup

On first run, open:
```
http://localhost:8080/setup
```

Create the initial admin user. After that, log in at:
```
http://localhost:8080/login
```

Admin can create additional users in the Admin page.

## Release Notes

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

### Docker Compose file selection

`make docker-up`, `make docker-down`, and `make restart` use `COMPOSE_FILE` from the Makefile.

- Default in this repository: `docker-compose-env.yml`
- Current checked-in Compose file: `docker-compose.yml`

If you want to use the checked-in file, pass it explicitly:

```bash
make docker-up COMPOSE_FILE=docker-compose.yml
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

- The application does not provide TLS/HTTPS by default.
- Server-side encryption relies on a single `MASTER_PASSWORD` from the environment (not per-user).
- No built-in rate limiting or brute-force protection is implemented.
- This project must be placed behind a reverse proxy with HTTPS if used outside of a local environment.

## macOS TouchID/FaceID helper (CLI)

This is optional and works with the current `/auth/biometric-unlock` endpoint.

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
export PM_SERVER_URL="http://127.0.0.1:8080/auth/biometric-token"
export PM_USER_EMAIL="your-user@example.com"
./bin/macos-unlock --server
```

This will prompt TouchID/FaceID, read the master password from Keychain, and return a short-lived token to the web UI.


## Production Considerations

If adapting this project for production use, you should:

- Enforce HTTPS via reverse proxy (Nginx, Traefik, etc.)
- Use per-user encryption keys and a proper key management scheme
- Add rate limiting and authentication hardening
- Review and audit cryptographic implementation

## Disclaimer

This software is provided as-is without warranty of any kind.
The author is not responsible for data loss, security breaches, or misuse of this software.
