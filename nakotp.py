#!/usr/bin/env python3
import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

CONFIG_FILE = Path.home() / ".nakotp"

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

def get_code(ip):
    """Fetch OTP code from device."""
    url = f"http://{ip}/"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        raise ConnectionError(f"Failed to connect to {ip}: {e}")

def main():
    config = load_config()
    min_expiry = config.get("min_expiry_seconds", 5)

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
            data = get_code(ip)
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
        break

if __name__ == "__main__":
    main()
