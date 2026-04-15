#!/bin/bash
# Deploy nakotp to the Raspberry Pi.
# Usage: PI_HOST=nasbox ./deploy.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="aarch64-unknown-linux-gnu"
BINARY="target/${TARGET}/release/nakotp"
SERVICE_FILE="${SCRIPT_DIR}/nakotp.service"
PI_HOST="${PI_HOST:-nasbox}"

echo "==> Building for ${TARGET}..."
cargo build --release --target "${TARGET}"

echo "==> Copying binary and service file to ${PI_HOST}..."
scp "${BINARY}" "${PI_HOST}:/tmp/nakotp"
scp "${SERVICE_FILE}" "${PI_HOST}:/tmp/nakotp.service"

echo "==> Installing binary, service, and restarting..."
ssh "${PI_HOST}" bash << 'REMOTE'
set -e
sudo mv /tmp/nakotp /usr/local/bin/nakotp
sudo chmod 755 /usr/local/bin/nakotp

# Create dedicated user if it doesn't already exist
if ! id nakotp &>/dev/null; then
    sudo useradd -r -s /sbin/nologin nakotp
fi

sudo mv /tmp/nakotp.service /etc/systemd/system/nakotp.service
sudo systemctl daemon-reload
sudo systemctl enable nakotp
sudo systemctl restart nakotp
sudo systemctl status nakotp --no-pager
REMOTE

echo "==> Done."
