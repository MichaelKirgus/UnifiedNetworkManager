.PHONY: setup up down stop-api stop-web restart api-dev web-dev clean

# Install all dependencies across the monorepo
setup:
	@echo "Installing dependencies..."
	cd api && npm install
	cd webapp && npm install
	cd plugins/opnsense && npm install
	cd plugins/basic-auth && npm install
	cd plugins/secrets-provider && npm install
	cd plugins/icmp && npm install
	cd plugins/snmp && npm install
	cd plugins/swos && npm install
	@echo "Dependencies installed successfully."

# Start infrastructure (DB and Plugins)
up:
	@echo "Starting infrastructure..."
	@if command -v docker-compose &> /dev/null; then \
		sudo docker-compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin snmp-plugin swos-plugin; \
	else \
		sudo docker compose up -d postgres opnsense-plugin basic-auth-plugin secrets-provider-plugin icmp-plugin snmp-plugin swos-plugin; \
	fi
	@echo "Infrastructure is up."

down:
	@echo "Stopping infrastructure..."
	@if docker compose version &> /dev/null; then \
		sudo docker compose down; \
	elif command -v docker-compose &> /dev/null; then \
		sudo docker-compose down; \
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
		sudo docker compose down -v; \
	elif command -v docker-compose &> /dev/null; then \
		sudo docker-compose down -v; \
	else \
		echo "Error: No docker-compose or docker compose found"; \
		exit 1; \
	fi
	rm -rf api/node_modules webapp/node_modules plugins/opnsense/node_modules plugins/basic-auth/node_modules plugins/secrets-provider/node_modules plugins/icmp/node_modules plugins/snmp/node_modules
	@echo "Cleanup complete."
