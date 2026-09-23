# nakotp

A TOTP authenticator that generates time-based one-time passwords (RFC 6238) and serves them over HTTPS. Two implementations are provided:

| Folder | Platform | Language |
|--------|----------|----------|
| `esp32/` | ESP8266 with SSD1306 OLED | C++ (Arduino / PlatformIO) |
| `pi-rust/` | Docker on Leia (formerly Raspberry Pi) | Rust |

## Support

If you find this useful, please consider buying me a coffee:

[![Donate with PayPal](https://www.paypalobjects.com/en_GB/i/btn/btn_donate_SM.gif)](https://www.paypal.com/donate?hosted_button_id=Q3BESC73EWVNN&custom=nakotp)

---

## ESP32 version (`esp32/`)

An ESP8266-based TOTP authenticator with an OLED display. Generates codes on-device and serves them over mTLS so a companion CLI (`nakotp.py`) can copy the current code to the clipboard.

### Hardware

- **Board:** ESP8266 (ESP-12E / Wemos D1 mini)
- **Display:** SSD1306 OLED (128×64, I2C)
- **Libraries:** TOTP library, NTPClient, Adafruit SSD1306/GFX

### Setup

1. Copy `esp32/src/secrets.h.template` → `esp32/src/secrets.h` and fill in your WiFi credentials and TOTP secret.
2. Run `esp32/certs/generate_certs.sh` to generate mTLS certificates.
3. Flash with PlatformIO: `pio run -t upload`

### Client

```bash
pip install rich
python3 esp32/nakotp.py
```

Fetches the current TOTP code from the device at `nakotp.local`, copies it to the clipboard, and clears it after the token expires.

---

## Rust version (`pi-rust/`)

A Rust web server that shows the current TOTP codes on a web page. Click a card, or press its number key (`1`, `2`, …), to copy that code to the clipboard.

### Deploying to Leia (current)

The server now runs as the `nakotp` Docker container on Leia, behind Leia's nginx at `https://nakotp.home.nakomis.com` (mutual TLS). The image is built from `docker-linux/Dockerfile` and pushed to a private ECR repository, which Leia pulls from. The ECR repository, compose service and config (`/mnt/data/nakotp/config.toml`, see `docker-linux/config.toml.example`) are managed in [home-infra](https://github.com/nakomis/home-infra).

```bash
./docker-linux/deploy.sh
```

This builds a `linux/amd64` image, pushes it to ECR as `:latest` (using the `nakom.is-admin` AWS profile), then pulls it on Leia and restarts the container.

### Raspberry Pi (legacy)

The instructions below are for the original Pi deployment, which is no longer in use.

It served the current TOTP code at `https://nakotp.nasbox.nakomis.com` using the wildcard Let's Encrypt certificate managed by the [nasbox](https://github.com/nakomis/nasbox) project.

#### Prerequisites

- Wildcard TLS certificate at `/etc/letsencrypt/live/nasbox.nakomis.com/` (see `nasbox/certificates/docs/setup.md`).
- Cross-compilation toolchain: `aarch64-linux-gnu-gcc` (install via `brew install aarch64-unknown-linux-gnu` on macOS).
- Rust target: `rustup target add aarch64-unknown-linux-gnu`

#### Configuration

Copy `pi-rust/config.example.toml` to `/etc/nakotp/config.toml` on the Pi and fill in your TOTP secret (hex-encoded bytes).

#### Building & deploying

```bash
cd pi-rust
PI_HOST=pi@nasbox.local ./deploy.sh
```

#### Running as a service

```bash
sudo cp pi-rust/nakotp.service /etc/systemd/system/
sudo useradd -r -s /sbin/nologin nakotp
sudo systemctl daemon-reload
sudo systemctl enable --now nakotp
```

Add a certbot post-renewal hook so the service restarts when the certificate renews:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/post/reload-nakotp.sh << 'EOF'
#!/bin/bash
systemctl restart nakotp
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/reload-nakotp.sh
```

---

## Licence

[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.
