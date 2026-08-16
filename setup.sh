#!/bin/bash

# Exit on error
set -e

echo "🚀 Starting UnifiedNetworkManager Appliance Setup..."

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

# 6. Start remaining infrastructure
echo "🌐 Starting remaining infrastructure (Plugins)..."
if command -v docker-compose &> /dev/null; then
    sudo docker-compose up -d opnsense-plugin
else
    sudo docker compose up -d opnsense-plugin
fi

echo "--------------------------------------------------------------------------------"
echo "✅ Appliance Setup Complete!"
echo "--------------------------------------------------------------------------------"
echo "The database is running and healthy on port 5432."
echo ""
echo "To start the application, please open two new terminals and run:"
echo ""
echo "Terminal 1 (API):   make api-dev"
echo "Terminal 2 (Web):   make web-dev"
echo "--------------------------------------------------------------------------------"
echo ""
echo "Press [ENTER] to stop the infrastructure and all dev servers..."
read -r
echo "🛑 Stopping everything..."
make stop-api
make stop-web
make down
echo "✅ All services stopped. Goodbye!"
