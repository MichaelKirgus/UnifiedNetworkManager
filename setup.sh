#!/bin/bash

# Exit on error
set -e

# --- Configuration -----------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PORT=3000
WEB_PORT=5173
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/unm-dev.XXXXXX")"
DEV_PIDS=()

# Plugin service discovery — NO hard-coded plugin list in this script. The set
# of plugins and their host ports are read from docker-compose.yml at start
# time, so a third-party plugin added to the compose file is picked up here
# (waited for + exported to the dev API) with zero changes to setup.sh.
declare -A PLUGIN_PORTS=()   # service name -> published TCP port
PLUGIN_SERVICES=()           # ordered list of discovered plugin services

discover_plugin_services() {
  if ! command -v node &> /dev/null; then
    fail "node is required (the dev workflow runs the API/webapp with npm)."
  fi
  local lines svc port
  # One line per service: "<name> <published-tcp-port>" — parsed from the
  # canonical compose JSON, so it always matches what actually gets deployed.
  if ! lines="$(docker_compose config --format json 2>/dev/null | node -e '
    let d = "";
    process.stdin.on("data", (c) => (d += c)).on("end", () => {
      const j = JSON.parse(d);
      for (const [name, svc] of Object.entries(j.services)) {
        if (!name.endsWith("-plugin")) continue;
        const tcp = (svc.ports ?? []).find((p) => p.protocol === "tcp" && p.published);
        if (tcp) console.log(name + " " + String(tcp.published));
      }
    });
  ')"; then
    fail "Could not parse docker-compose.yml (needs Docker Compose v2 with 'config --format json')."
  fi
  [ -n "$lines" ] || fail "No *-plugin services with a published TCP port found in docker-compose.yml."
  while read -r svc port; do
    PLUGIN_PORTS["$svc"]="$port"
    PLUGIN_SERVICES+=("$svc")
  done <<< "$lines"
}

# Comma-separated `service:port` pairs for the dev API's endpoint rewrite
# (api/src/utils/pluginEndpoint.ts reads PLUGIN_HOST_PORT_MAP).
build_host_port_map() {
  local out="" svc
  for svc in "${PLUGIN_SERVICES[@]}"; do
    [ -n "$out" ] && out+=","
    out+="${svc}:${PLUGIN_PORTS[$svc]}"
  done
  printf '%s' "$out"
}

# All TCP ports to free during cleanup (API + webapp + every discovered plugin).
all_dev_ports() {
  local svc
  echo "${API_PORT}" "${WEB_PORT}"
  for svc in "${PLUGIN_SERVICES[@]}"; do echo "${PLUGIN_PORTS[$svc]}"; done
}

# --- Helpers -----------------------------------------------------------------
ok()   { echo "✅ $1"; }
fail() { echo "❌ $1"; exit 1; }

# --- Docker privilege handling ------------------------------------------------
# Prefer running Docker WITHOUT sudo — `sudo` may prompt for a password and block
# this unattended script, so we only escalate when we genuinely cannot reach the
# daemon otherwise. The decision is made once at startup.
if ! command -v docker &> /dev/null; then
  fail "Docker is not installed."
fi

# Empty prefix = no sudo (we can talk to Docker directly). We get direct access
# when we're in the `docker` group or already have daemon access.
if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker || docker info &> /dev/null 2>&1; then
  DOCKER_SUDO=""
else
  DOCKER_SUDO="sudo"
fi

# Run a docker compose command (v2 plugin or legacy binary) with the chosen prefix.
docker_compose() {
  if [ -n "$DOCKER_SUDO" ]; then S="$DOCKER_SUDO"; else S=""; fi
  if command -v docker-compose &> /dev/null; then
    $S docker-compose "$@"
  else
    $S docker compose "$@"
  fi
}

# Start the Docker daemon if it is down. Starting a system service needs root,
# so this may use sudo even when routine compose commands don't — but only in that
# (rare) case, never for everyday operations.
ensure_docker_daemon() {
  if docker info &> /dev/null 2>&1; then return 0; fi   # already up + reachable
  echo "⚠️  Docker daemon is not running. Attempting to start it..."
  local started=0
  if [ -n "$DOCKER_SUDO" ]; then
    $DOCKER_SUDO systemctl start docker && started=1 || true
  else
    sudo systemctl start docker && started=1 || true   # group member still needs root for this
  fi
  if [ "$started" -ne 1 ]; then
    echo "❌ Could not start Docker automatically. Start it manually (e.g. 'sudo systemctl start docker') and re-run."
    exit 1
  fi
  local i=0
  until docker info &> /dev/null 2>&1; do
    i=$((i + 1))
    if [ $i -ge 15 ]; then echo "❌ Docker daemon took too long to respond."; exit 1; fi
    echo -n "."; sleep 1
  done
  ok "Docker daemon is now responsive."
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

# Kill every dev process belonging to this repo, using several independent
# strategies and then VERIFYING nothing survived (retry loop).
#
# A single fire-and-forget pkill is not enough in practice:
#   - ts-node-dev's respawn supervisor can re-spawn a worker between kills,
#   - hard-killed setup.sh runs (double Ctrl+C / closed terminal) skip the
#     EXIT trap entirely, so leftovers accumulate across sessions and keep
#     polling Postgres even with no port bound (device status flapping).
# Called both on cleanup (exit) and as pre-flight before starting.
kill_dev_processes() {
  local round=0 pid cwd p

  while [ "$round" -lt 4 ]; do
    # Strategy 1 (most precise): kill any node/npm process whose working
    # directory is inside this repo — catches supervisors, workers and vite
    # regardless of how their command line looks. Editor processes (VS Code
    # extension host runs as `node` with the workspace as cwd) are excluded.
    for pid in $(pgrep -x node 2>/dev/null; pgrep -x npm 2>/dev/null); do
      cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
      case "$cwd" in
        "$ROOT"/*)
          cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
          case "$cmdline" in
            *vscode*|*extensionHost*|*/Code/|*cursor*) : ;; # never kill the editor
            *) kill -9 "$pid" 2>/dev/null || true ;;
          esac
          ;;
      esac
    done

    # Strategy 2: free the dev ports (kills whatever is actually serving).
    # Plugin ports are discovered from docker-compose.yml at start of run;
    # on a first-ever cleanup they may be empty — API/webapp still covered.
    for p in $(all_dev_ports); do
      fuser -k "${p}/tcp" >/dev/null 2>&1 || true
    done

    # Strategy 3: command-line patterns. Repo-scoped first, then unscoped
    # fallbacks so no dev-server variant (vite, ts-node-dev) survives.
    pkill -9 -f "UnifiedNetworkManager.*(ts-node-dev|vite)" >/dev/null 2>&1 || true
    pkill -9 -f "ts-node-dev" >/dev/null 2>&1 || true
    pkill -9 -f "[v]ite" >/dev/null 2>&1 || true

    sleep 1

    # Verify: nothing matching is left → done.
    if ! pgrep -f "ts-node-dev|vite" >/dev/null 2>&1; then
      return 0
    fi
    round=$((round + 1))
  done

  echo "⚠️  Some dev processes survived the cleanup — please kill them manually:"
  pgrep -af "ts-node-dev|vite" | grep -v pgrep || true
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
  kill_dev_processes
  docker_compose down || true
  rm -rf "$LOG_DIR" 2>/dev/null || true
  echo "✅ All services stopped. Goodbye!"
}
trap cleanup EXIT INT TERM

# --- Pre-flight: kill lingering processes from previous runs -----------------
# An aborted/crashed setup.sh can leave orphaned dev servers holding ports
# 3000/5173. Every subsequent run then fails with EADDRINUSE while the OLD
# code keeps serving — so always start from a clean slate.
kill_lingering() {
  # Stale compose containers (e.g. an old api container publishing :3000)
  # must go first — they are root-owned and outlive any host-side pkill/fuser.
  docker_compose down || true
  kill_dev_processes
}

echo "🚀 Starting UnifiedNetworkManager dev environment..."
discover_plugin_services
echo "🔎 Discovered ${#PLUGIN_SERVICES[@]} plugin services: ${PLUGIN_SERVICES[*]}"
kill_lingering

# 1. Environment Check
echo "🔍 Checking environment..."
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Error: docker-compose is not installed. Please install it to continue."
    exit 1
fi

ensure_docker_daemon

# 2. Install dependencies
echo "📦 Installing dependencies..."
make setup

# 3. Spin up the Database Instance
echo "🗄️  Spinning up PostgreSQL database instance..."
docker_compose up -d postgres

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

# 6. Build shared package + plugins in parallel (see the `build` make target).
echo "🔨 Building plugins..."
make build
ok "Plugins + MCP server built (in parallel)."

# 7. Start the plugin containers (--build: always reflect current source;
#    reusing stale images silently serves old code — a past source of bugs).
#    The service list is DISCOVERED from docker-compose.yml above — adding a
#    third-party plugin there is all that's needed to have it built + waited on.
echo "🌐 Starting plugin containers..."
docker_compose up -d --build mcp "${PLUGIN_SERVICES[@]}"
ok "Plugin + MCP containers started."

# 8. Wait for the plugins to be reachable (basic-auth must be up before the
#    API can verify credentials; secrets-provider before secret access).
echo "⏳ Waiting for plugins to be ready..."
for svc in "${PLUGIN_SERVICES[@]}"; do
  wait_for_port "${PLUGIN_PORTS[$svc]}" "$svc"
done
ok "Plugins are reachable."

# 8b. Wait for the MCP server (diagnostic endpoints for AI agents).
echo "⏳ Waiting for the MCP server to be ready on port 3901..."
wait_for_port 3901 "mcp"
ok "MCP server is up (POST :3901/mcp, POST :3901/debug/mcp)."

# 9. Start the API and webapp dev servers (hot reload) in the background.
# The API runs on the HOST, so it cannot resolve compose service names —
# PLUGIN_HOST_PORT_MAP tells its endpoint resolver which localhost port each
# published plugin lives on (built from the same discovery as above).
echo "🚦 Starting API and webapp dev servers..."
export PLUGIN_HOST_PORT_MAP="$(build_host_port_map)"
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
echo "  MCP:     http://localhost:3901/mcp (debug: /debug/mcp, key: dev-mcp-debug-key)"
echo "  Logs:    $LOG_DIR"
echo ""
echo "  • API dev log:   tail -f $LOG_DIR/api.log"
echo "  • Web dev log:   tail -f $LOG_DIR/web.log"
echo ""
echo "  Press [ENTER] (or Ctrl+C) to stop the dev servers and all containers."
echo "--------------------------------------------------------------------------------"
read -r
# Teardown is handled by the cleanup() trap (EXIT/INT/TERM).
