#!/usr/bin/env python3
import json
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from subprocess import DEVNULL
from pathlib import Path

DEVICE_HOST = "nakotp.local"
CERTS_DIR = Path.home() / ".nakotp-certs"
MIN_EXPIRY_SECONDS = 5

def copy_to_clipboard(text):
    subprocess.run(["pbcopy"], input=text.encode(), check=True)

def clear_clipboard():
    subprocess.run(["pbcopy"], stdin=DEVNULL, check=True)

def get_ssl_context():
    """Create SSL context with client certificate."""
    ca_cert = CERTS_DIR / "ca.crt"
    client_pem = CERTS_DIR / "client.pem"

    if not ca_cert.exists() or not client_pem.exists():
        print(f"Error: Certificates not found in {CERTS_DIR}")
        print(f"Run: mkdir -p {CERTS_DIR}")
        print(f"Then copy ca.crt and client.pem from the certs/ folder")
        sys.exit(1)

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    ctx.load_cert_chain(certfile=str(client_pem))
    ctx.check_hostname = False
    return ctx

def get_code(host, ssl_context):
    """Fetch OTP code from device via HTTPS."""
    url = f"https://{host}/"
    try:
        with urllib.request.urlopen(url, timeout=15, context=ssl_context) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ssl.SSLError) as e:
        raise ConnectionError(f"Failed to connect to {host}: {e}")

def main():
    clear_clipboard()
    ssl_context = get_ssl_context()

    while True:
        try:
            data = get_code(DEVICE_HOST, ssl_context)
        except ConnectionError as e:
            print(f"Connection failed: {e}")
            sys.exit(1)

        code = data["code"]
        expires_at = data["expires_at"]

        # Check expiry
        now = time.time()
        seconds_remaining = expires_at - now

        if seconds_remaining < MIN_EXPIRY_SECONDS:
            print(f"Code expires in {seconds_remaining:.1f}s, waiting for new code...")
            time.sleep(seconds_remaining + 0.5)
            continue

        # Success
        copy_to_clipboard(code)
        print(f"{code} (copied, expires in {int(seconds_remaining)}s)")
        print('\a')
        break

if __name__ == "__main__":
    main()
