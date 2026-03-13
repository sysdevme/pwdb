# PWDB Desktop

Standalone Wails-based desktop client scaffold for macOS, kept in the same repository as the server and controller.

## Current scope

- Target platform: macOS
- Development can happen on Linux/Debian, but real GUI testing should happen on the Mac laptop
- Current implementation is a read-only shell:
  - remembers `server_url` and `email`
  - tests server reachability
  - prepares the structure for the initial desktop JSON API

## What is already here

- standalone `desktop/go.mod`
- Wails app bootstrap
- config persistence under the user's config directory
- simple connection test against `/login`
- frontend shell for node selection and future vault view
- `build_macos.sh` helper for dependency install + macOS build

## What is still missing

- desktop frontend wiring to the new API
- token storage in macOS Keychain
- polished item copy/view flows

## Current server API for desktop MVP

- `POST /api/desktop/login`
- `POST /api/desktop/logout`
- `GET /api/desktop/passwords`
- `GET /api/desktop/passwords/:id`
- `POST /api/desktop/passwords/:id/unlock`

Current model:

- desktop login uses the same server-side session storage as the web app
- desktop auth is sent as `Authorization: Bearer <session-token>`
- password list/detail endpoints return metadata
- plaintext secret retrieval is separated into `/unlock` and requires `master_password`

Example login:

```bash
curl -sS -X POST "http://127.0.0.1:8080/api/desktop/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"login-password"}'
```

Example list:

```bash
curl -sS "http://127.0.0.1:8080/api/desktop/passwords" \
  -H "Authorization: Bearer <session-token>"
```

Example unlock:

```bash
curl -sS -X POST "http://127.0.0.1:8080/api/desktop/passwords/<id>/unlock" \
  -H "Authorization: Bearer <session-token>" \
  -H "Content-Type: application/json" \
  -d '{"master_password":"master-password"}'
```

Do not build the desktop client on top of HTML parsing or browser-cookie emulation if this can be avoided.

## Build on macOS Tahoe

Prerequisites:

- Go
- Node.js + npm
- Xcode Command Line Tools
- network access for Go/npm dependencies

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

## Notes

- This scaffold is intentionally safe and incomplete.
- It should be treated as the desktop foundation, not as a finished client.
- The next practical step is wiring the frontend to the desktop API and then extending the API to notes and richer session handling.
