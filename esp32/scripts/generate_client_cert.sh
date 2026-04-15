#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <client-name>"
    echo "Example: $0 myphone"
    exit 1
fi

CLIENT_NAME="$1"
CERTS_DIR="$(cd "$(dirname "$0")/../certs" && pwd)"
OUTPUT_DIR="${2:-$CERTS_DIR}"

# Check CA exists
if [ ! -f "$CERTS_DIR/ca.crt" ] || [ ! -f "$CERTS_DIR/ca.key" ]; then
    echo "Error: CA certificates not found in $CERTS_DIR"
    echo "Run generate_certs.sh first"
    exit 1
fi

# Configuration (match main cert script)
DAYS_VALID=3650
EC_CURVE="prime256v1"
COUNTRY="US"
STATE="State"
CITY="City"
ORG="NakOTP"

echo "=== Generating Client Certificate for '$CLIENT_NAME' ==="

openssl ecparam -name $EC_CURVE -genkey -noout -out "$OUTPUT_DIR/$CLIENT_NAME.key"
openssl req -new -key "$OUTPUT_DIR/$CLIENT_NAME.key" -out "$OUTPUT_DIR/$CLIENT_NAME.csr" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CLIENT_NAME"
openssl x509 -req -days $DAYS_VALID -in "$OUTPUT_DIR/$CLIENT_NAME.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial -out "$OUTPUT_DIR/$CLIENT_NAME.crt"

# Create combined PEM
cat "$OUTPUT_DIR/$CLIENT_NAME.crt" "$OUTPUT_DIR/$CLIENT_NAME.key" > "$OUTPUT_DIR/$CLIENT_NAME.pem"

# Clean up CSR
rm -f "$OUTPUT_DIR/$CLIENT_NAME.csr"

echo ""
echo "=== Done ==="
echo "Created:"
echo "  $OUTPUT_DIR/$CLIENT_NAME.crt  (certificate)"
echo "  $OUTPUT_DIR/$CLIENT_NAME.key  (private key)"
echo "  $OUTPUT_DIR/$CLIENT_NAME.pem  (combined for clients)"
