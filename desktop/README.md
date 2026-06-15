# PWDB Desktop

Standalone Wails-based desktop client for macOS, kept in the same repository as the server and controller.

## Current scope

- Target platform: macOS.
- Development and package tests can run on Linux, but real GUI and biometric testing require macOS.
- The client is currently read-only and supports:
  - saved server URL and email settings;
  - server reachability checks;
  - login and logout through the desktop JSON API;
  - password and secure-note lists;
  - metadata detail views;
  - master-password confirmation before secret fields are revealed.

Session tokens currently remain in process memory. Persistent macOS Keychain storage is still pending.

## Server API

- `POST /api/desktop/login`
- `POST /api/desktop/logout`
- `GET /api/desktop/passwords`
- `GET /api/desktop/passwords/:id`
- `POST /api/desktop/passwords/:id/unlock`
- `GET /api/desktop/notes`
- `GET /api/desktop/notes/:id`
- `POST /api/desktop/notes/:id/unlock`

Desktop authentication uses `Authorization: Bearer <session-token>`. List and detail endpoints return metadata; plaintext retrieval is isolated in `/unlock` requests and requires `master_password`.

## Build on macOS Tahoe

Prerequisites:

- Go 1.22 or newer
- Node.js and npm
- Xcode Command Line Tools
- Wails build dependencies
- network access for dependency installation

Run:

```bash
cd desktop
chmod +x build_macos.sh
./build_macos.sh
```

For development:

```bash
cd desktop/frontend
npm install
cd ..
wails dev
```

For package verification:

```bash
cd desktop
go test ./...
go vet ./...
```

## Remaining work

- Store desktop session tokens in macOS Keychain.
- Polish copy actions and item detail workflows.
- Add automated tests for the desktop HTTP client and config store.
- Validate the packaged GUI and biometric flow on macOS hardware.
