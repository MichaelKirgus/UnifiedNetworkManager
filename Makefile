.PHONY: setup build test up down stop-api stop-web restart api-dev web-dev clean

# Every real plugin directory = plugins/* with a package.json (the _template
# starter is excluded by name). Adding a third-party plugin folder is all that's
# needed — no Makefile edit. Compose service names follow the <name>-plugin
# convention, so the up target derives them from this list too.
PLUGINS := $(filter-out _template,$(notdir $(patsubst %/,%,$(dir $(wildcard plugins/*/package.json)))))

# Install all dependencies across the monorepo (in parallel — each folder has
# its own node_modules, so there are no cross-folder races).
setup:
	@echo "Installing dependencies..."
	@( \
	  (cd packages/plugin-sdk && npm install) & \
	  (cd packages/snmp-client && npm install) & \
	  (cd packages/lancom-shared && npm install) & \
	  (cd packages/plugin-test-kit && npm install) & \
	  (cd api && npm install) & \
	  (cd webapp && npm install) & \
	  (cd mcp && npm install) & \
	  $(foreach p,$(PLUGINS),(cd plugins/$(p) && npm install) & ) \
	  wait )
	@echo "Dependencies installed successfully."

# Build the shared packages + all plugins + the MCP server + api + webapp.
#
# Ordering: @unm/plugin-sdk and @unm/snmp-client must build FIRST — every
# plugin (and the api, types-only) depends on them via `file:` links, which npm
# COPIES into node_modules at install time. @unm/lancom-shared builds after both
# (it depends on each). We refresh those copies from the fresh dist before
# building the plugins so they compile against current shared code; everything
# else then runs concurrently (tsc builds are CPU-bound and independent of
# each other). The api and webapp join the parallel section — their file: deps
# were already refreshed above, and both build with plain tsc.
build:
	@echo "Building @unm/plugin-sdk + @unm/snmp-client..."
	cd packages/plugin-sdk && npm run build
	cd packages/snmp-client && npm run build
	@echo "Building @unm/lancom-shared..."
	cd packages/lancom-shared && npm run build
	@echo "Refreshing file:-linked copies in dependent plugins + api..."
	for p in $(PLUGINS); do \
	  rm -rf plugins/$$p/node_modules/@unm/plugin-sdk; \
	  cp -r packages/plugin-sdk plugins/$$p/node_modules/@unm/plugin-sdk; \
	done
	# SNMP-based plugins (depend on @unm/snmp-client) — derived from PLUGINS so a
	# new snmp plugin only needs to be added to this one filter list.
	for p in $(filter generic-snmp lancom-%,$(PLUGINS)); do \
	  rm -rf plugins/$$p/node_modules/@unm/snmp-client; \
	  cp -r packages/snmp-client plugins/$$p/node_modules/@unm/snmp-client; \
	done
	# Lancom MIB-sharing plugins (depend on @unm/lancom-shared).
	for p in $(filter lancom-%,$(PLUGINS)); do \
	  rm -rf plugins/$$p/node_modules/@unm/lancom-shared; \
	  cp -r packages/lancom-shared plugins/$$p/node_modules/@unm/lancom-shared; \
	done
	rm -rf api/node_modules/@unm/plugin-sdk; \
	cp -r packages/plugin-sdk api/node_modules/@unm/plugin-sdk
	# POSIX sh (no arrays): PIDs are collected as a space-separated string and
	# each one is waited on individually — a bare `wait` would return 0 if ANY
	# job succeeded, silently hiding type errors in the other jobs.
	@echo "Building plugins + MCP server + api + webapp in parallel..."
	@( \
	  pids=""; \
	  for p in $(PLUGINS); do (cd plugins/$$p && npm run build) & pids="$$pids $$!"; done; \
	  (cd mcp && npm run build) & pids="$$pids $$!"; \
	  (cd api && npm run build) & pids="$$pids $$!"; \
	  (cd webapp && npm run build) & pids="$$pids $$!"; \
	  fail=0; \
	  for pid in $$pids; do wait $$pid || fail=1; done; \
	  exit $$fail )
	@echo "Build complete."

# Run the offline test suites (no Docker / live services required):
#   1. API unit checks (IP math)
#   2. The standardized per-plugin contract suite — every built plugin is
#      spawned standalone against in-process mock appliances and checked for
#      fatal flaws (healthz, /discover validation, monitoring happy-path +
#      dead-target handling). Requires `make build` first (tests dist/ output).
#   3. API unit tests (jest) — pure utilities, no DB needed.
#   4. Webapp unit tests (vitest) — pure utilities, no DOM needed.
test:
	./node_modules/.bin/tsx scripts/verify-ip-math.ts
	node packages/plugin-test-kit/bin/run-all.mjs
	cd api && npm test
	cd webapp && npm test

# Just the per-plugin contract suite (see packages/plugin-test-kit/README.md).
plugin-tests:
	node packages/plugin-test-kit/bin/run-all.mjs

# Start infrastructure (DB and Plugins). The plugin service list follows the
# <name>-plugin compose convention derived from PLUGINS — no hand-maintained list.
# NOTE: no sudo here — setup.sh detects whether the current user can reach the
# Docker daemon directly (docker group) and only escalates when truly needed.
up:
	@echo "Starting infrastructure..."
	@if command -v docker-compose >/dev/null 2>&1; then \
		docker-compose -f docker-compose.dev.yml up -d postgres mcp $(addsuffix -plugin,$(PLUGINS)); \
	else \
		docker compose -f docker-compose.dev.yml up -d postgres mcp $(addsuffix -plugin,$(PLUGINS)); \
	fi
	@echo "Infrastructure is up."

down:
	@echo "Stopping infrastructure..."
	@if docker compose version >/dev/null 2>&1; then \
		docker compose -f docker-compose.dev.yml down; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		docker-compose -f docker-compose.dev.yml down; \
	else \
		echo "Error: No docker-compose or docker compose found"; \
		exit 1; \
	fi

restart: down up

# Sync this checkout to GitHub's main and redeploy: pull --ff-only (fails loudly
# instead of merging when the tree has local edits — this VM/build machine is
# expected to stay a clean mirror), rebuild everything, then recreate only the
# containers whose source actually changed. The dev loop is: edit + test on the
# workstation -> git push -> make sync here.
sync:
	@echo "Checking working tree..."
	@if [ -n "$$(git status --porcelain | grep -v 'package-lock.json' || true)" ]; then \
	  echo "Error: uncommitted changes present (see above) — commit or stash them first."; \
	  exit 1; \
	fi
	@echo "Pulling origin/main (ff-only)..."
	git pull --ff-only origin main
	HEAD=$$(git rev-parse HEAD); \
	LAST=$$(cat .last-synced-commit 2>/dev/null || echo ""); \
	if [ -z "$$LAST" ]; then \
	  echo "First sync — rebuilding everything."; \
	  CHANGED="api webapp mcp $(addsuffix -plugin,$(PLUGINS))"; \
	else \
	  echo "Changes since last sync ($$LAST -> $$HEAD):"; \
	  git diff --name-only $$LAST..$$HEAD | grep -v '^package-lock.json$$' || true; \
	fi
	@echo "Building..."
	$(MAKE) build
	# Recreate the core services (api/webapp/mcp) plus every plugin whose source
	# changed since the last sync; a first sync (no marker file) recreates all.
	# POSIX sh: no `case`/`for` inside line-continuations (dash parses them as
	# one physical line — see the &> history); the mapping runs in its own
	# script with real newlines.
	@rm -f .sync-changed-files .sync-services .sync-services-final
	@if [ -z "$$LAST" ]; then \
	  echo "api webapp mcp $(addsuffix -plugin,$(PLUGINS))" > .sync-services; \
	else \
	  git diff --name-only $$LAST..$$HEAD | grep -v '^package-lock.json$$' > .sync-changed-files || true; \
	  sh scripts/sync-map-services.sh < .sync-changed-files > .sync-services; \
	fi
	@cat .sync-services | sort -u | tr '\n' ' ' > .sync-services-final
	@if grep -qx ALL .sync-services 2>/dev/null; then \
	  echo "api webapp mcp $(addsuffix -plugin,$(PLUGINS))" > .sync-services-final; \
	fi
	SERVICES=$$(cat .sync-services-final); \
	echo "Recreating: $$SERVICES"; \
	if [ "$$SERVICES" != "" ]; then \
	  docker compose -f docker-compose.dev.yml up -d --build $$SERVICES; \
	fi
	git rev-parse HEAD > .last-synced-commit
	@echo "Sync complete at $$(git log -1 --format='%h %s')"

stop-api:
	@echo "Stopping API server..."
	-fuser -k 3000/tcp
	@echo "API port 3000 cleared."

stop-web:
	@echo "Stopping Webapp server..."
	-fuser -k 8080/tcp
	@echo "Webapp port 8080 cleared."

# Run API in dev mode (with hot reload)
api-dev:
	@echo "Starting API in dev mode..."
	cd api && npm run dev

# Run Webapp in dev mode (with hot reload)
web-dev:
	@echo "Starting Webapp in dev mode..."
	cd webapp && npm run dev

# Clean up everything
clean:
	@echo "Cleaning up..."
	@if docker compose version >/dev/null 2>&1; then \
		docker compose -f docker-compose.dev.yml down -v; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		docker-compose -f docker-compose.dev.yml down -v; \
	else \
		echo "Error: No docker-compose or docker compose found"; \
		exit 1; \
	fi
	rm -rf api/node_modules webapp/node_modules mcp/node_modules packages/plugin-sdk/node_modules packages/snmp-client/node_modules packages/lancom-shared/node_modules $(foreach p,$(PLUGINS),plugins/$(p)/node_modules)
	@echo "Cleanup complete."
