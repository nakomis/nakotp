#!/bin/bash
# Build a linux/amd64 nakotp image, push it to ECR, and restart nakotp on Leia.
# Leia's gateway compose pulls ${NAKOTP_IMAGE} (<ecr-uri>:latest) — see
# home-infra/leia/deployment/docker-compose.yml.
# Usage: [LEIA_HOST=leia] [AWS_PROFILE=nakom.is-admin] ./deploy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LEIA_HOST="${LEIA_HOST:-leia}"
AWS_PROFILE="${AWS_PROFILE:-nakom.is-admin}"
AWS_REGION="${AWS_REGION:-eu-west-2}"
GATEWAY_DIR="/mnt/data/gateway"

echo "==> Looking up ECR repository URI..."
REPO_URI="$(aws ssm get-parameter --name /nakotp/ecr/registry-uri \
  --query Parameter.Value --output text \
  --region "$AWS_REGION" --profile "$AWS_PROFILE")"
REGISTRY="${REPO_URI%%/*}"

echo "==> Logging in to $REGISTRY..."
aws ecr get-login-password --region "$AWS_REGION" --profile "$AWS_PROFILE" \
  | docker login --username AWS --password-stdin "$REGISTRY"

echo "==> Building and pushing linux/amd64 image to $REPO_URI:latest..."
docker buildx build \
  --platform linux/amd64 \
  -f "$SCRIPT_DIR/Dockerfile" \
  -t "$REPO_URI:latest" \
  --push \
  "$REPO_ROOT"

echo "==> Pulling and restarting nakotp on $LEIA_HOST..."
ssh "$LEIA_HOST" "cd $GATEWAY_DIR && docker compose pull nakotp && docker compose up -d nakotp"

echo "==> Done."
