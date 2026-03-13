#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

need_cmd go
need_cmd npm

if ! command -v wails >/dev/null 2>&1; then
  echo "Wails CLI not found. Installing..."
  go install github.com/wailsapp/wails/v2/cmd/wails@latest
  export PATH="$(go env GOPATH)/bin:$PATH"
fi

need_cmd wails

cd "$ROOT_DIR"

echo "==> Resolving Go modules"
go mod tidy

echo "==> Installing frontend dependencies"
cd frontend
npm install
cd "$ROOT_DIR"

echo "==> Building macOS app"
wails build -platform darwin/universal

echo "Build complete."
