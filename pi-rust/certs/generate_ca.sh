#!/bin/bash
# Generate the NakOTP Pi private CA.
# Run this once on your Mac, then deploy with deploy.sh which will copy ca.crt to the Pi.
# Keep ca.key safe — it never leaves your Mac.
set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERTS_DIR"

DAYS_VALID=3650
EC_CURVE="prime256v1"
ORG="NakOTP"

echo "=== Generating CA ==="
openssl ecparam -name $EC_CURVE -genkey -noout -out ca.key
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt \
    -subj "/O=$ORG/CN=NakOTP-Pi-CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo ""
echo "=== Generating initial client certificate ==="
bash "$(dirname "$0")/generate_client_cert.sh" client

echo ""
echo "=== Done ==="
echo ""
echo "Next steps:"
echo "  1. Run deploy.sh — it will copy ca.crt to /etc/nakotp/ca.crt on the Pi"
echo "  2. Set client_ca_cert = \"/etc/nakotp/ca.crt\" in /etc/nakotp/config.toml"
echo "  3. Restart: ssh nasbox sudo systemctl restart nakotp"
echo "  4. Import client.p12 into macOS Keychain (password: nakotp)"
echo "  5. Trust the CA: sudo security add-trusted-cert -d -r trustRoot \\"
echo "         -k /Library/Keychains/System.keychain $CERTS_DIR/ca.crt"
echo ""
echo "Back up everything to S3:"
echo "  bash $CERTS_DIR/s3sync.sh"
