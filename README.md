# nakotp

An ESP8266-based TOTP authenticator with an OLED display. Generates time-based one-time passwords (RFC 6238) on-device and serves them over mTLS so a companion CLI (`nakotp.py`) can copy the current code directly to your clipboard.

## Support

If you find this useful, please consider buying me a coffee:

[![Donate with PayPal](https://www.paypalobjects.com/en_GB/i/btn/btn_donate_SM.gif)](https://www.paypal.com/donate?hosted_button_id=Q3BESC73EWVNN)

## Hardware

- **Board:** ESP8266 (ESP-12E / Wemos D1 mini)
- **Display:** SSD1306 OLED (128×64, I2C)
- **Libraries:** TOTP library, NTPClient, Adafruit SSD1306/GFX

## Usage

```bash
python3 nakotp.py
```

Fetches the current TOTP code from the device at `nakotp.local`, copies it to the clipboard, and clears it after the token expires.

## Licence

[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.
