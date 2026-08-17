#!/bin/bash

# Exit on error
set -e

# --- Configuration -----------------------------------------------------------
API_PORT=3000
WEB_PORT=5173
OPNSENSE_PORT=4001
BASIC_AUTH_PORT=4002
SECRETS_PORT=4003
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/unm-dev.XXXXXX")"
DEV_PIDS=()

# --- Helpers -----------------------------------------------------------------
ok()   { echo "✅ $1"; }
fail() { echo "❌ $1"; exit 1; }

# Run a docker compose command (v2 plugin or legacy binary), with sudo.
docker_compose() {
  if command -v docker-compose &> /dev/null; then
    sudo docker-compose "$@"
  else
    sudo docker compose "$@"
  fi
}

# Wait until a TCP port accepts connections.
wait_for_port() {
  local port="$1" name="$2" retries="${3:-30}" i=0
  until nc -z localhost "$port" 2>/dev/null; do
    i=$((i+1))
    if [ "$i" -ge "$retries" ]; then
      fail "$name did not open port $port within ${retries}s."
    fi
    echo -n "."; sleep 1
  done
}

# Wait until an HTTP endpoint responds successfully.
wait_for_url() {
  local url="$1" name="$2" retries="${3:-30}" i=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    i=$((i+1))
    if [ "$i" -ge "$retries" ]; then
      fail "$name did not become ready at $url within ${retries}s."
    fi
    echo -n "."; sleep 1
  done
}

# Start a dev server in its own session so the whole process tree can be killed
# cleanly on exit (setsid makes the PID the session/process-group leader).
start_dev_server() {
  local dir="$1" name="$2"
  if command -v setsid &> /dev/null; then
    setsid bash -c "cd '$dir' && exec npm run dev" > "$LOG_DIR/$name.log" 2>&1 &
  else
    bash -c "cd '$dir' && exec npm run dev" > "$LOG_DIR/$name.log" 2>&1 &
  fi
  DEV_PIDS+=("$!")
}

# --- Cleanup (idempotent; stops dev servers + containers) --------------------
cleanup() {
  trap - EXIT INT TERM
  echo ""
  echo "🛑 Stopping dev servers and containers..."
  for pid in "${DEV_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
    fi
  done
  # Safety nets: free the dev ports and kill any respawn supervisors.
  fuser -k "${API_PORT}/tcp" 2>/dev/null || true
  fuser -k "${WEB_PORT}/tcp" 2>/dev/null || true
  pkill -f "ts-node-dev" 2>/dev/null || true
  pkill -f "vite" 2>/dev/null || true
  sleep 1
  docker_compose down || true
  rm -rf "$LOG_DIR" 2>/dev/null || true
  echo "✅ All services stopped. Goodbye!"
}
trap cleanup EXIT INT TERM

echo "🚀 Starting UnifiedNetworkManager dev environment..."

# 1. Environment Check
echo "🔍 Checking environment..."
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed. Please install Docker to continue."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Error: docker-compose is not installed. Please install it to continue."
    exit 1
fi

if ! sudo docker info &> /dev/null; then
    echo "⚠️  Docker daemon is not running. Attempting to start it..."
    if sudo systemctl start docker; then
        echo "✅ Start command sent. Waiting for daemon to initialize..."
        
        # Wait for Docker to actually be ready
        MAX_DOCKER_RETRIES=15
        DOCKER_COUNT=0
        until sudo docker info &> /dev/null; do
          DOCKER_COUNT=$((DOCKER_COUNT + 1))
          if [ $DOCKER_COUNT -ge $MAX_DOCKER_RETRIES ]; then
            echo "❌ Error: Docker daemon took too long to respond."
            exit 1
          fi
          echo -n "."
          sleep 1
        done
        echo "✅ Docker daemon is now responsive."
    else
        echo "❌ Error: Failed to start Docker daemon. Please start it manually (e.g., 'sudo systemctl start docker')."
        exit 1
    fi
fi

# 2. Install dependencies
echo "📦 Installing dependencies..."
make setup

# 3. Spin up the Database Instance
echo "🗄️  Spinning up PostgreSQL database instance..."
if command -v docker-compose &> /dev/null; then
    sudo docker-compose up -d postgres
else
    sudo docker compose up -d postgres
fi

# 4. Database Health Check
echo "⏳ Waiting for Postgres to be ready on port 5432..."
MAX_RETRIES=30
COUNT=0
until nc -z localhost 5432; do
  COUNT=$((COUNT + 1))
  if [ $COUNT -ge $MAX_RETRIES ]; then
    echo "❌ Error: Postgres failed to start within $MAX_RETRIES seconds."
    exit 1
  fi
  echo -n "."
  sleep 1
done
echo "✅ Postgres is online and ready!"

# 5. Sync Database Schema
echo "🛠️  Syncing database schema..."
cd api && npx drizzle-kit push && cd ..
echo "✅ Database schema is up to date."

# 6. Build the plugins (opnsense + basic-auth + secrets-provider)
echo "🔨 Building plugins..."
( cd plugins/opnsense && npm run build )
( cd plugins/basic-auth && npm run build )
( cd plugins/secrets-provider && npm run build )
ok "Plugins built (opnsense + basic-auth + secrets-provider)."

# 7. Start the plugin containers
echo "🌐 Starting plugin containers..."
docker_compose up -d opnsense-plugin basic-auth-plugin secrets-provider-plugin
ok "Plugin containers started."

# 8. Wait for the plugins to be reachable (basic-auth must be up before the
#    API can verify credentials; secrets-provider before secret access;
#    opnsense is needed for device telemetry).
echo "⏳ Waiting for plugins to be ready..."
wait_for_port "$OPNSENSE_PORT" "opnsense-plugin"
wait_for_port "$BASIC_AUTH_PORT" "basic-auth-plugin"
wait_for_port "$SECRETS_PORT" "secrets-provider-plugin"
ok "Plugins are reachable."

# 9. Start the API and webapp dev servers (hot reload) in the background.
echo "🚦 Starting API and webapp dev servers..."
start_dev_server "api" "api"
start_dev_server "webapp" "web"

echo "⏳ Waiting for the API to be ready on port ${API_PORT}..."
wait_for_port "$API_PORT" "API"
wait_for_url "http://localhost:${API_PORT}/healthz" "API"
ok "API is up."

echo "⏳ Waiting for the webapp to be ready on port ${WEB_PORT}..."
wait_for_port "$WEB_PORT" "webapp"
ok "Webapp is up."

echo "--------------------------------------------------------------------------------"
echo "✅ Dev environment is running!"
echo "--------------------------------------------------------------------------------"
echo "  Webapp:  http://localhost:${WEB_PORT}"
echo "  API:     http://localhost:${API_PORT}/v1"
echo "  Logs:    $LOG_DIR"
echo ""
echo "  • API dev log:   tail -f $LOG_DIR/api.log"
echo "  • Web dev log:   tail -f $LOG_DIR/web.log"
echo ""
echo "  Press [ENTER] (or Ctrl+C) to stop the dev servers and all containers."
echo "--------------------------------------------------------------------------------"
read -r
# Teardown is handled by the cleanup() trap (EXIT/INT/TERM).
