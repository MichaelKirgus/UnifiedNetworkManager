.PHONY: setup build test up down stop-api stop-web restart api-dev web-dev clean

# Install all dependencies across the monorepo (in parallel — each folder has
# its own node_modules, so there are no cross-folder races).
setup:
	@echo "Installing dependencies..."
	@( \
	  (cd packages/plugin-sdk && npm install) & \
	  (cd packages/snmp-client && npm install) & \
	  (cd packages/lancom-shared && npm install) & \
	  (cd api && npm install) & \
	  (cd webapp && npm install) & \
	  (cd plugins/opnsense && npm install) & \
	  (cd plugins/basic-auth && npm install) & \
	  (cd plugins/secrets-provider && npm install) & \
	  (cd plugins/file-repo && npm install) & \
	  (cd plugins/icmp && npm install) & \
	  (cd plugins/generic-snmp && npm install) & \
	  (cd plugins/lancom-lx && npm install) & \
	  (cd plugins/lancom-lcos && npm install) & \
	  (cd plugins/mikrotik-swos && npm install) & \
	  (cd plugins/fbox && npm install) & \
	  (cd plugins/mikrotik-routeros && npm install) & \
	  (cd plugins/docker && npm install) & \
	  (cd plugins/openwrt && npm install) & \
	  (cd plugins/generic-ssh && npm install) & \
	  (cd plugins/generic-http && npm install) & \
	  (cd plugins/generic-ntp && npm install) & \
	  (cd plugins/flow-collector && npm install) & \
	  (cd plugins/mailcow && npm install) & \
	  (cd plugins/zabbix && npm install) & \
	  (cd mcp && npm install) & \
	  wait )
	@echo "Dependencies installed successfully."

# Build the shared packages + all plugins + the MCP server.
#
# Ordering: @unm/plugin-sdk and @unm/snmp-client must build FIRST — every
# plugin (and the api, types-only) depends on them via `file:` links, which npm
# COPIES into node_modules at install time. @unm/lancom-shared builds after both
# (it depends on each). We refresh those copies from the fresh dist before
# building the plugins so they compile against current shared code; everything
# else then runs concurrently (tsc builds are CPU-bound and independent of
# each other).
build:
	@echo "Building @unm/plugin-sdk + @unm/snmp-client..."
	cd packages/plugin-sdk && npm run build
	cd packages/snmp-client && npm run build
	@echo "Building @unm/lancom-shared..."
	cd packages/lancom-shared && npm run build
	@echo "Refreshing file:-linked copies in dependent plugins + api..."
	for p in icmp generic-snmp lancom-lx lancom-sx lancom-lcos opnsense mikrotik-swos fbox ix-truenas mikrotik-routeros docker openwrt generic-ssh generic-http generic-ntp flow-collector mailcow zabbix basic-auth secrets-provider file-repo; do \
	  rm -rf plugins/$$p/node_modules/@unm/plugin-sdk; \
	  cp -r packages/plugin-sdk plugins/$$p/node_modules/@unm/plugin-sdk; \
	done
	for p in generic-snmp lancom-lx lancom-sx lancom-lcos; do \
	  rm -rf plugins/$$p/node_modules/@unm/snmp-client; \
	  cp -r packages/snmp-client plugins/$$p/node_modules/@unm/snmp-client; \
	done
	for p in lancom-lx lancom-sx lancom-lcos; do \
	  rm -rf plugins/$$p/node_modules/@unm/lancom-shared; \
	  cp -r packages/lancom-shared plugins/$$p/node_modules/@unm/lancom-shared; \
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
	  (cd plugins/file-repo && npm run build) & \
	  (cd plugins/mikrotik-swos && npm run build) & \
	  (cd plugins/fbox && npm run build) & \
	  (cd plugins/ix-truenas && npm run build) & \
	  (cd plugins/mikrotik-routeros && npm run build) & \
	  (cd plugins/docker && npm run build) & \
	  (cd plugins/openwrt && npm run build) & \
	  (cd plugins/generic-ssh && npm run build) & \
	  (cd plugins/generic-http && npm run build) & \
	  (cd plugins/generic-ntp && npm run build) & \
	  (cd plugins/flow-collector && npm run build) & \
	  (cd plugins/mailcow && npm run build) & \
	  (cd plugins/zabbix && npm run build) & \
	  (cd mcp && npm run build) & \
	  wait )
	@echo "Build complete."

# Run the offline test suites (no Docker / live services required).
test:
	./node_modules/.bin/tsx scripts/verify-ip-math.ts

# Start infrastructure (DB and Plugins).
# NOTE: no sudo here — setup.sh detects whether the current user can reach the
# Docker daemon directly (docker group) and only escalates when truly needed.
up:
	@echo "Starting infrastructure..."
	@if command -v docker-compose &> /dev/null; then \
		docker-compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin file-repo-plugin icmp-plugin generic-snmp-plugin lancom-lx-plugin lancom-sx-plugin lancom-lcos-plugin mikrotik-swos-plugin fbox-plugin ix-truenas-plugin mikrotik-routeros-plugin docker-plugin openwrt-plugin generic-ssh-plugin mailcow-plugin zabbix-plugin mcp; \
	else \
		docker compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin file-repo-plugin icmp-plugin generic-snmp-plugin lancom-lx-plugin lancom-sx-plugin lancom-lcos-plugin mikrotik-swos-plugin fbox-plugin ix-truenas-plugin mikrotik-routeros-plugin docker-plugin openwrt-plugin generic-ssh-plugin mailcow-plugin zabbix-plugin mcp; \
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
	rm -rf api/node_modules webapp/node_modules mcp/node_modules packages/plugin-sdk/node_modules packages/snmp-client/node_modules packages/lancom-shared/node_modules plugins/opnsense/node_modules plugins/basic-auth/node_modules plugins/secrets-provider/node_modules plugins/icmp/node_modules plugins/generic-snmp/node_modules plugins/mikrotik-swos/node_modules plugins/fbox/node_modules plugins/ix-truenas/node_modules plugins/mikrotik-routeros/node_modules plugins/lancom-lx/node_modules plugins/lancom-sx/node_modules plugins/lancom-lcos/node_modules plugins/openwrt/node_modules plugins/generic-ssh/node_modules plugins/mailcow/node_modules
	@echo "Cleanup complete."
