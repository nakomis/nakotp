#!/bin/bash
# Deploy nakotp to the Raspberry Pi.
# Usage: PI_HOST=pi@nasbox.local ./deploy.sh
set -e

TARGET="aarch64-unknown-linux-gnu"
BINARY="target/${TARGET}/release/nakotp"
PI_HOST="${PI_HOST:-pi@nasbox.local}"

echo "==> Building for ${TARGET}..."
cargo build --release --target "${TARGET}"

echo "==> Copying binary to ${PI_HOST}..."
scp "${BINARY}" "${PI_HOST}:/tmp/nakotp"

echo "==> Installing and restarting service..."
ssh "${PI_HOST}" "sudo mv /tmp/nakotp /usr/local/bin/nakotp && sudo systemctl restart nakotp"

echo "==> Done."
