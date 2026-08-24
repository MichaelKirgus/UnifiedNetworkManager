.PHONY: setup build up down stop-api stop-web restart api-dev web-dev clean

# Install all dependencies across the monorepo (in parallel — each folder has
# its own node_modules, so there are no cross-folder races).
setup:
	@echo "Installing dependencies..."
	@( \
	  (cd packages/snmp-client && npm install) & \
	  (cd api && npm install) & \
	  (cd webapp && npm install) & \
	  (cd plugins/opnsense && npm install) & \
	  (cd plugins/basic-auth && npm install) & \
	  (cd plugins/secrets-provider && npm install) & \
	  (cd plugins/icmp && npm install) & \
	  (cd plugins/snmp && npm install) & \
	  (cd plugins/lancom-lx && npm install) & \
	  (cd plugins/swos && npm install) & \
	  (cd mcp && npm install) & \
	  wait )
	@echo "Dependencies installed successfully."

# Build the shared package + all plugins + the MCP server.
#
# Ordering: @unm/snmp-client must build FIRST — the snmp and lancom-lx plugins
# depend on it via `file:` links, which npm COPIES into their node_modules at
# install time. We refresh those copies from the fresh dist before building the
# plugins so they compile against current shared code; everything else then runs
# concurrently (tsc builds are CPU-bound and independent of each other).
build:
	@echo "Building @unm/snmp-client..."
	cd packages/snmp-client && npm run build
	@echo "Refreshing file:-linked copies in dependent plugins..."
	for p in snmp lancom-lx; do \
	  rm -rf plugins/$$p/node_modules/@unm/snmp-client; \
	  cp -r packages/snmp-client plugins/$$p/node_modules/@unm/snmp-client; \
	done
	@echo "Building plugins + MCP server in parallel..."
	@( \
	  (cd plugins/opnsense && npm run build) & \
	  (cd plugins/icmp && npm run build) & \
	  (cd plugins/snmp && npm run build) & \
	  (cd plugins/lancom-lx && npm run build) & \
	  (cd plugins/basic-auth && npm run build) & \
	  (cd plugins/secrets-provider && npm run build) & \
	  (cd plugins/swos && npm run build) & \
	  (cd mcp && npm run build) & \
	  wait )
	@echo "Build complete."

# Start infrastructure (DB and Plugins).
# NOTE: no sudo here — setup.sh detects whether the current user can reach the
# Docker daemon directly (docker group) and only escalates when truly needed.
up:
	@echo "Starting infrastructure..."
	@if command -v docker-compose &> /dev/null; then \
		docker-compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin snmp-plugin lancom-lx-plugin swos-plugin mcp; \
	else \
		docker compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin snmp-plugin lancom-lx-plugin swos-plugin mcp; \
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
	rm -rf api/node_modules webapp/node_modules mcp/node_modules plugins/opnsense/node_modules plugins/basic-auth/node_modules plugins/secrets-provider/node_modules plugins/icmp/node_modules plugins/snmp/node_modules plugins/lancom-lx/node_modules
	@echo "Cleanup complete."
