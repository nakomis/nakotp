#!/bin/bash
set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERTS_DIR"

echo "Generating certificates in $CERTS_DIR"

# Configuration
DAYS_VALID=3650
KEY_SIZE=2048
COUNTRY="US"
STATE="State"
CITY="City"
ORG="NakOTP"

# Clean up old certs
rm -f *.pem *.key *.crt *.h

echo "=== Generating CA ==="
openssl genrsa -out ca.key $KEY_SIZE
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=NakOTP-CA"

echo "=== Generating Server Certificate ==="
openssl genrsa -out server.key $KEY_SIZE
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=nakotp-device"
openssl x509 -req -days $DAYS_VALID -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

echo "=== Generating Client Certificate ==="
openssl genrsa -out client.key $KEY_SIZE
openssl req -new -key client.key -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=nakotp-client"
openssl x509 -req -days $DAYS_VALID -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt

# Create combined PEM for Python client
cat client.crt client.key > client.pem

# Clean up CSRs
rm -f *.csr *.srl

echo "=== Generating C header for ESP8266 ==="
cat > server_certs.h << 'HEADER_START'
#ifndef SERVER_CERTS_H
#define SERVER_CERTS_H

// Auto-generated - do not edit manually
// Run generate_certs.sh to regenerate

HEADER_START

# Server certificate
echo "const char server_cert[] PROGMEM = R\"EOF(" >> server_certs.h
cat server.crt >> server_certs.h
echo ")EOF\";" >> server_certs.h
echo "" >> server_certs.h

# Server private key
echo "const char server_key[] PROGMEM = R\"EOF(" >> server_certs.h
cat server.key >> server_certs.h
echo ")EOF\";" >> server_certs.h
echo "" >> server_certs.h

# CA certificate (for verifying client certs)
echo "const char ca_cert[] PROGMEM = R\"EOF(" >> server_certs.h
cat ca.crt >> server_certs.h
echo ")EOF\";" >> server_certs.h
echo "" >> server_certs.h

echo "#endif" >> server_certs.h

# Copy header to src
cp server_certs.h ../src/

echo ""
echo "=== Done ==="
echo "Files created:"
echo "  ca.crt        - CA certificate (install on client for trust)"
echo "  ca.key        - CA private key (keep secure)"
echo "  server.crt    - Server certificate"
echo "  server.key    - Server private key"
echo "  client.crt    - Client certificate"
echo "  client.key    - Client private key"
echo "  client.pem    - Combined client cert+key for Python"
echo "  server_certs.h - C header for ESP8266 (copied to src/)"
echo ""
echo "For Python client, copy these to ~/.nakotp-certs/:"
echo "  mkdir -p ~/.nakotp-certs"
echo "  cp ca.crt client.pem ~/.nakotp-certs/"
