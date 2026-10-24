#!/usr/bin/env bash
set -euo pipefail

echo "==> Starting infrastructure (Postgres + Redis)..."
docker compose -f deploy/docker-compose.yml up -d

echo "==> Waiting for services to be healthy..."
sleep 3

echo "==> Done. You can now run:"
echo "    cargo run -p control"
echo "    cargo run -p edge"
echo "    cd apps/frontend && npm run dev"
