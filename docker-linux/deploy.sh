#!/bin/bash
# Build a linux/amd64 nakotp image on this machine and load it onto Leia.
# Usage: [LEIA_HOST=leia] ./deploy.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LEIA_HOST="${LEIA_HOST:-leia}"

echo "==> Building linux/amd64 image..."
docker buildx build \
  --platform linux/amd64 \
  -f "$SCRIPT_DIR/Dockerfile" \
  -t nakotp:latest \
  --output type=docker \
  "$REPO_ROOT" | ssh "$LEIA_HOST" docker load

echo "==> Restarting nakotp on $LEIA_HOST..."
ssh "$LEIA_HOST" "cd ~/gateway && docker compose up -d nakotp"

echo "==> Done."
