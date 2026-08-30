.PHONY: setup build up down stop-api stop-web restart api-dev web-dev clean

# Install all dependencies across the monorepo (in parallel — each folder has
# its own node_modules, so there are no cross-folder races).
setup:
	@echo "Installing dependencies..."
	@( \
	  (cd packages/plugin-sdk && npm install) & \
	  (cd packages/snmp-client && npm install) & \
	  (cd api && npm install) & \
	  (cd webapp && npm install) & \
	  (cd plugins/opnsense && npm install) & \
	  (cd plugins/basic-auth && npm install) & \
	  (cd plugins/secrets-provider && npm install) & \
	  (cd plugins/icmp && npm install) & \
	  (cd plugins/generic-snmp && npm install) & \
	  (cd plugins/lancom-lx && npm install) & \
	  (cd plugins/lancom-lcos && npm install) & \
	  (cd plugins/mikrotik-swos && npm install) & \
	  (cd plugins/fbox && npm install) & \
	  (cd mcp && npm install) & \
	  wait )
	@echo "Dependencies installed successfully."

# Build the shared packages + all plugins + the MCP server.
#
# Ordering: @unm/plugin-sdk and @unm/snmp-client must build FIRST — every
# plugin (and the api, types-only) depends on them via `file:` links, which npm
# COPIES into node_modules at install time. We refresh those copies from the
# fresh dist before building the plugins so they compile against current shared
# code; everything else then runs concurrently (tsc builds are CPU-bound and
# independent of each other).
build:
	@echo "Building @unm/plugin-sdk + @unm/snmp-client..."
	cd packages/plugin-sdk && npm run build
	cd packages/snmp-client && npm run build
	@echo "Refreshing file:-linked copies in dependent plugins + api..."
	for p in icmp snmp lancom-lx lancom-sx lancom-cos opnsense swos fbox basic-auth secrets-provider; do \
	  rm -rf plugins/$$p/node_modules/@unm/plugin-sdk; \
	  cp -r packages/plugin-sdk plugins/$$p/node_modules/@unm/plugin-sdk; \
	done
	for p in snmp lancom-lx lancom-sx lancom-lcos; do \
	  rm -rf plugins/$$p/node_modules/@unm/snmp-client; \
	  cp -r packages/snmp-client plugins/$$p/node_modules/@unm/snmp-client; \
	done
	rm -rf api/node_modules/@unm/plugin-sdk; \
	cp -r packages/plugin-sdk api/node_modules/@unm/plugin-sdk
	@echo "Building plugins + MCP server in parallel..."
	@( \
	  (cd plugins/opnsense && npm run build) & \
	  (cd plugins/icmp && npm run build) & \
	  (cd plugins/generic-snmp && npm run build) & \
	  (cd plugins/lancom-lx && npm run build) & \
	  (cd plugins/lancom-sx && npm run build) & \
	  (cd plugins/lancom-lcos && npm run build) & \
	  (cd plugins/basic-auth && npm run build) & \
	  (cd plugins/secrets-provider && npm run build) & \
	  (cd plugins/mikrotik-swos && npm run build) & \
	  (cd plugins/fbox && npm run build) & \
	  (cd mcp && npm run build) & \
	  wait )
	@echo "Build complete."

# Start infrastructure (DB and Plugins).
# NOTE: no sudo here — setup.sh detects whether the current user can reach the
# Docker daemon directly (docker group) and only escalates when truly needed.
up:
	@echo "Starting infrastructure..."
	@if command -v docker-compose &> /dev/null; then \
		docker-compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin generic-snmp-plugin lancom-lx-plugin lancom-sx-plugin lancom-cos-plugin mikrotik-swos-plugin fbox-plugin mcp; \
	else \
		docker compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin generic-snmp-plugin lancom-lx-plugin lancom-sx-plugin lancom-cos-plugin mikrotik-swos-plugin fbox-plugin mcp; \
	fi
	@echo "Infrastructure is up."

down:
	@echo "Stopping infrastructure..."
	@if docker compose version &> /dev/null; then \
		docker compose down; \
	elif command -v docker-compose &> /dev/null; then \
		docker-compose down; \
	else \
		echo "Error: No docker-compose or docker compose found"; \
		exit 1; \
	fi

restart: down up

stop-api:
	@echo "Stopping API server..."
	-fuser -k 3000/tcp
	@echo "API port 3000 cleared."

stop-web:
	@echo "Stopping Webapp server..."
	-fuser -k 5173/tcp
	@echo "Webapp port 5173 cleared."

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
	@if docker compose version &> /dev/null; then \
		docker compose down -v; \
	elif command -v docker-compose &> /dev/null; then \
		docker-compose down -v; \
	else \
		echo "Error: No docker-compose or docker compose found"; \
		exit 1; \
	fi
	rm -rf api/node_modules webapp/node_modules mcp/node_modules plugins/opnsense/node_modules plugins/basic-auth/node_modules plugins/secrets-provider/node_modules plugins/icmp/node_modules plugins/generic-snmp/node_modules plugins/mikrotik-swos/node_modules plugins/fbox/node_modules plugins/lancom-lx/node_modules plugins/lancom-sx/node_modules plugins/lancom-cos/node_modules
	@echo "Cleanup complete."
