export AWS_PROFILE=mh
CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"
aws s3 sync "$CERTS_DIR" s3://nak-sandbox-certs/nakotp-pi \
    --exclude "*.sh"
