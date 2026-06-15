# PWDB TODO

Last reviewed: 2026-06-15

## Completed

- [x] Password and secure-note CRUD.
- [x] Tags, groups, search, and pagination.
- [x] Multi-user lifecycle, roles, sessions, sharing, and internal messages.
- [x] Argon2id password hashing and AES-GCM encryption.
- [x] Admin backup/restore and 1Password `.1pif` import.
- [x] Admin Guard and login-attempt blocking.
- [x] Experimental AS-M/AS-S topology and embedded controller.
- [x] Desktop JSON API for login, passwords, notes, and secret unlock.
- [x] Wails desktop frontend wired to the desktop API.
- [x] 4.1.0 security review fixes: admin-only node mode, authenticated controller management, ownership checks, split controller auth, SSRF protection, atomic setup, and transactional restore.

## P0 - Security And Reproducibility

- [x] Fail startup when `MASTER_PASSWORD` is empty.
- [x] Add CSRF protection to browser POST forms.
- [x] Track applied SQL migrations with checksums and per-migration transactions.
- [x] Commit reproducible desktop Go dependency metadata (`desktop/go.sum`).

## P1 - Tests And CI

### Dependency Security

- [ ] Upgrade `github.com/jackc/pgx/v5` from `5.5.5` to at least `5.9.2` to resolve Dependabot alerts [#6](https://github.com/sysdevme/pwdb/security/dependabot/6) (critical memory-safety issue) and [#7](https://github.com/sysdevme/pwdb/security/dependabot/7) (SQL placeholder confusion).
- [ ] Upgrade `golang.org/x/crypto` from `0.22.0` to at least `0.45.0` to resolve Dependabot alerts [#1](https://github.com/sysdevme/pwdb/security/dependabot/1), [#2](https://github.com/sysdevme/pwdb/security/dependabot/2), [#3](https://github.com/sysdevme/pwdb/security/dependabot/3), and [#4](https://github.com/sysdevme/pwdb/security/dependabot/4).
- [ ] Re-run root tests, `go vet`, and Dependabot verification after dependency upgrades.

### Test And CI Work

- [ ] Add rollback tests for setup failure and restore failure.
- [ ] Add PostgreSQL integration tests for migrations, sharing, setup, and restore.
- [ ] Add HTTP tests for login, sessions, admin handlers, and desktop API.
- [ ] Add unit tests for crypto, importer, desktop client, and config store.
- [ ] Add GitHub Actions for root, controller, desktop, and frontend builds.
- [x] Commit frontend lockfile and use reproducible npm installs.

## P2 - Architecture And Operations

- [ ] Split `internal/handlers/handlers.go` by domain.
- [ ] Add HTTP `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`.
- [x] Move the external `collection` service to a Compose profile or override.
- [ ] Add TLS/mTLS and rate limiting for controller APIs.
- [ ] Replace snapshot-only controller sync with per-record delta events.
- [ ] Implement delete propagation and full convergence cleanup.

## Import

- [ ] Map 1Password password history to archived passwords after schema support is added.
- [ ] Add mappings for additional 1Password 7 secure-note types when samples are available.

## Desktop

- [ ] Store the desktop session token in macOS Keychain.
- [ ] Polish copy and item-view workflows.
- [ ] Test the real GUI and biometric flow on macOS.
- [ ] Keep `desktop/README.md` aligned with the implemented API and UI.

## UI

- [ ] Implement the firewall setting or remove the placeholder control.
