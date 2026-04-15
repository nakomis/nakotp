#!/bin/bash
# Deploy nakotp to the Raspberry Pi.
# Usage: PI_HOST=nasbox ./deploy.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="aarch64-unknown-linux-gnu"
BINARY="target/${TARGET}/release/nakotp"
SERVICE_FILE="${SCRIPT_DIR}/nakotp.service"
EXAMPLE_CONFIG="${SCRIPT_DIR}/config.example.toml"
PI_HOST="${PI_HOST:-nasbox}"

echo "==> Building for ${TARGET}..."
cargo build --release --target "${TARGET}"

echo "==> Copying binary, service file, and example config to ${PI_HOST}..."
scp "${BINARY}" "${PI_HOST}:/tmp/nakotp"
scp "${SERVICE_FILE}" "${PI_HOST}:/tmp/nakotp.service"
scp "${EXAMPLE_CONFIG}" "${PI_HOST}:/tmp/nakotp.config.example.toml"

echo "==> Installing binary, service, and restarting..."
ssh "${PI_HOST}" bash << 'REMOTE'
set -e
sudo mv /tmp/nakotp /usr/local/bin/nakotp
sudo chmod 755 /usr/local/bin/nakotp

# Create dedicated user if it doesn't already exist
if ! id nakotp &>/dev/null; then
    sudo useradd -r -s /sbin/nologin nakotp
fi

# Install example config if no real config exists yet
sudo mkdir -p /etc/nakotp
if [ ! -f /etc/nakotp/config.toml ]; then
    sudo mv /tmp/nakotp.config.example.toml /etc/nakotp/config.toml
    echo ""
    echo "*** ACTION REQUIRED ***"
    echo "No config found. Installed example config at /etc/nakotp/config.toml"
    echo "Edit it (especially hmac_key_hex) before the service will work."
    echo ""
    CONFIG_NEEDED=1
else
    rm -f /tmp/nakotp.config.example.toml
    CONFIG_NEEDED=0
fi

sudo mv /tmp/nakotp.service /etc/systemd/system/nakotp.service
sudo systemctl daemon-reload
sudo systemctl enable nakotp

if [ "${CONFIG_NEEDED}" = "1" ]; then
    echo "Skipping start until config is filled in."
else
    sudo systemctl restart nakotp
    sudo systemctl status nakotp --no-pager
fi
REMOTE

echo "==> Done."
