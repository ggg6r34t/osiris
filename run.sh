#!/usr/bin/env bash
#
# Osiris web UI — one-command production start.
#
# Starts the FastAPI backend (port 8000) and the Next.js production server
# (port 3000), builds the frontend if needed, and shuts both down cleanly on
# Ctrl+C. This runs the *production* servers (no dev/--reload), so it is snappier
# and more stable than the two-terminal dev workflow.
#
# Usage:
#   ./run.sh            # build frontend if missing, then start both servers
#   ./run.sh --build    # force a fresh frontend production build first
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Load local secrets/config if present (gitignored) — e.g. OSIRIS_PANDA_* keys.
if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

BACKEND_PORT="${OSIRIS_BACKEND_PORT:-8000}"
FRONTEND_PORT="${OSIRIS_FRONTEND_PORT:-3000}"

# Resolve the backend interpreter/uvicorn (prefer the project venv).
if [ -x "$ROOT/venv/bin/uvicorn" ]; then
  UVICORN="$ROOT/venv/bin/uvicorn"
elif command -v uvicorn >/dev/null 2>&1; then
  UVICORN="uvicorn"
else
  echo "error: uvicorn not found. Create the venv and install deps:" >&2
  echo "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && pip install -e ." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "error: npm not found. Install Node.js (>=18) to run the frontend." >&2
  exit 1
fi

# Frontend deps + production build.
cd "$ROOT/web"
[ -d node_modules ] || { echo "→ Installing frontend dependencies…"; npm install; }
if [ "${1:-}" = "--build" ] || [ ! -d .next ]; then
  echo "→ Building frontend (production)…"
  npm run build
fi
cd "$ROOT"

BACK_PID=""
FRONT_PID=""
cleanup() {
  echo ""
  echo "→ Shutting down…"
  [ -n "$FRONT_PID" ] && kill "$FRONT_PID" 2>/dev/null || true
  [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null || true
  # Also kill anything left holding the ports (e.g. the next-server child
  # process that npm spawns and that outlives its parent shell).
  lsof -ti:"$BACKEND_PORT" 2>/dev/null | xargs kill 2>/dev/null || true
  lsof -ti:"$FRONTEND_PORT" 2>/dev/null | xargs kill 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "→ Starting API on http://127.0.0.1:${BACKEND_PORT}"
"$UVICORN" osiris.api:app --host 127.0.0.1 --port "$BACKEND_PORT" &
BACK_PID=$!

echo "→ Starting web UI on http://localhost:${FRONTEND_PORT}"
( cd "$ROOT/web" && npm run start -- --port "$FRONTEND_PORT" ) &
FRONT_PID=$!

echo ""
echo "Osiris is running — open http://localhost:${FRONTEND_PORT}  (Ctrl+C to stop)"

# Wait until either server exits, then fall through to cleanup. Uses a poll loop
# (not `wait -n`) so it works on macOS's default bash 3.2.
while kill -0 "$BACK_PID" 2>/dev/null && kill -0 "$FRONT_PID" 2>/dev/null; do
  sleep 1
done
