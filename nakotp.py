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

CONFIG_FILE = Path.home() / ".nakotp"
CERTS_DIR = Path.home() / ".nakotp-certs"

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def expand_ip(partial):
    """Expand partial IP to full IP starting with 10.0."""
    partial = partial.strip()
    parts = partial.split(".")

    if len(parts) == 1:
        return f"10.0.0.{parts[0]}"
    elif len(parts) == 2:
        return f"10.0.{parts[0]}.{parts[1]}"
    elif len(parts) == 3:
        return f"10.{parts[0]}.{parts[1]}.{parts[2]}"
    else:
        return partial

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

def get_code(ip, ssl_context):
    """Fetch OTP code from device via HTTPS."""
    url = f"https://{ip}/"
    try:
        with urllib.request.urlopen(url, timeout=15, context=ssl_context) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ssl.SSLError) as e:
        raise ConnectionError(f"Failed to connect to {ip}: {e}")

def main():
    clear_clipboard();
    config = load_config()
    min_expiry = config.get("min_expiry_seconds", 5)

    ssl_context = get_ssl_context()

    while True:
        # START: Get IP
        ip = config.get("ip")

        if not ip:
            partial = input("Enter device IP (or partial, e.g. '70' for 10.0.0.70): ").strip()
            if not partial:
                print("No IP provided, exiting.")
                sys.exit(1)
            ip = expand_ip(partial)
            config["ip"] = ip
            save_config(config)
            print(f"Using IP: {ip}")

        # GET_CODE
        try:
            data = get_code(ip, ssl_context)
        except ConnectionError as e:
            print(f"Connection failed: {e}")
            print("Clearing saved IP...")
            config.pop("ip", None)
            save_config(config)
            continue

        code = data["code"]
        expires_at = data["expires_at"]

        # Check expiry
        now = time.time()
        seconds_remaining = expires_at - now

        if seconds_remaining < min_expiry:
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
