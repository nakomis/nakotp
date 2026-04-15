#!/bin/bash
# Generate a client certificate signed by the NakOTP Pi CA.
# Usage: ./generate_client_cert.sh <name>
# Example: ./generate_client_cert.sh martin-iphone
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <client-name>"
    echo "Example: $0 martin-iphone"
    exit 1
fi

CLIENT_NAME="$1"
CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$CERTS_DIR/ca.crt" ] || [ ! -f "$CERTS_DIR/ca.key" ]; then
    echo "Error: CA not found in $CERTS_DIR. Run generate_ca.sh first."
    exit 1
fi

DAYS_VALID=3650
EC_CURVE="prime256v1"
ORG="NakOTP"

echo "=== Generating client certificate for '$CLIENT_NAME' ==="

openssl ecparam -name $EC_CURVE -genkey -noout -out "$CERTS_DIR/$CLIENT_NAME.key"
openssl req -new -key "$CERTS_DIR/$CLIENT_NAME.key" -out "$CERTS_DIR/$CLIENT_NAME.csr" \
    -subj "/O=$ORG/CN=$CLIENT_NAME"
openssl x509 -req -days $DAYS_VALID -sha256 \
    -in "$CERTS_DIR/$CLIENT_NAME.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial -out "$CERTS_DIR/$CLIENT_NAME.crt" \
    -extfile <(echo "extendedKeyUsage=clientAuth")

# Combined PEM (cert + key) for curl / Python clients
cat "$CERTS_DIR/$CLIENT_NAME.crt" "$CERTS_DIR/$CLIENT_NAME.key" > "$CERTS_DIR/$CLIENT_NAME.pem"

# PKCS#12 for browser / macOS Keychain import
openssl pkcs12 -export \
    -out "$CERTS_DIR/$CLIENT_NAME.p12" \
    -inkey "$CERTS_DIR/$CLIENT_NAME.key" \
    -in "$CERTS_DIR/$CLIENT_NAME.crt" \
    -certfile "$CERTS_DIR/ca.crt" \
    -passout pass:nakotp

rm -f "$CERTS_DIR/$CLIENT_NAME.csr"

echo ""
echo "=== Done ==="
echo "  $CLIENT_NAME.pem  — combined cert+key for curl / Python clients"
echo "  $CLIENT_NAME.p12  — for browser / macOS Keychain (password: nakotp)"
echo ""
echo "To import into macOS Keychain:"
echo "  open $CERTS_DIR/$CLIENT_NAME.p12"
echo "  (password: nakotp)"
