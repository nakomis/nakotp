#!/bin/bash
# Build a linux/amd64 nakotp image, push it to ECR, and restart nakotp on Leia.
# Leia's gateway compose pulls ${NAKOTP_IMAGE} (<ecr-uri>:latest) — see
# home-infra/leia/deployment/docker-compose.yml.
# Usage: [LEIA_HOST=leia] [NAKOTP_AWS_PROFILE=nakom.is-admin] ./deploy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LEIA_HOST="${LEIA_HOST:-leia}"
# Deliberately not AWS_PROFILE: that is often set to another account in the shell.
NAKOTP_AWS_PROFILE="${NAKOTP_AWS_PROFILE:-nakom.is-admin}"
NAKOTP_AWS_REGION="${NAKOTP_AWS_REGION:-eu-west-2}"
GATEWAY_DIR="/mnt/data/gateway"

echo "==> Looking up ECR repository URI..."
REPO_URI="$(aws ssm get-parameter --name /nakotp/ecr/registry-uri \
  --query Parameter.Value --output text \
  --region "$NAKOTP_AWS_REGION" --profile "$NAKOTP_AWS_PROFILE")"
REGISTRY="${REPO_URI%%/*}"

echo "==> Logging in to $REGISTRY..."
aws ecr get-login-password --region "$NAKOTP_AWS_REGION" --profile "$NAKOTP_AWS_PROFILE" \
  | docker login --username AWS --password-stdin "$REGISTRY"

echo "==> Building and pushing linux/amd64 image to $REPO_URI:latest..."
docker buildx build \
  --platform linux/amd64 \
  --progress=plain \
  -f "$SCRIPT_DIR/Dockerfile" \
  -t "$REPO_URI:latest" \
  --push \
  "$REPO_ROOT"

echo "==> Pulling and restarting nakotp on $LEIA_HOST..."
# sudo: the ECR credential helper is configured for root only (home-infra Leia playbook).
ssh "$LEIA_HOST" "cd $GATEWAY_DIR && sudo docker compose pull nakotp && sudo docker compose up -d nakotp"

echo "==> Done."
