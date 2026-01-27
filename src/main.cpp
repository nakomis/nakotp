#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <sha1.h>
#include "secrets.h"
#include "server_certs.h"

// OLED display settings
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SDA_PIN 14
#define SCL_PIN 12

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// NTP Client
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000);

// SSL certificates
BearSSL::X509List serverCertList(server_cert);
BearSSL::PrivateKey serverPrivKey(server_key);
BearSSL::X509List caCertList(ca_cert);

// HTTPS Server
BearSSL::WiFiServerSecure server(443);

// Custom TOTP implementation with configurable digits
String getTotp(long timeStamp) {
  long timeStep = timeStamp / 30;

  // Convert counter to big-endian bytes
  uint8_t challenge[8];
  for (int i = 7; i >= 0; i--) {
    challenge[i] = timeStep & 0xFF;
    timeStep >>= 8;
  }

  // HMAC-SHA1
  Sha1.initHmac(HMAC_KEY, HMAC_KEY_LEN);
  Sha1.write(challenge, 8);
  uint8_t* hash = Sha1.resultHmac();

  // Dynamic truncation
  int offset = hash[19] & 0x0F;
  long otp = ((hash[offset] & 0x7F) << 24) |
             ((hash[offset + 1] & 0xFF) << 16) |
             ((hash[offset + 2] & 0xFF) << 8) |
             (hash[offset + 3] & 0xFF);

  // Apply modulo based on digit count
  long divisor = 1;
  for (int i = 0; i < OTP_DIGITS; i++) divisor *= 10;
  otp = otp % divisor;

  // Pad with leading zeros
  char code[9];
  sprintf(code, "%0*ld", OTP_DIGITS, otp);
  return String(code);
}

String currentCode = "";
unsigned long lastCodeTime = 0;

void setup() {
  Serial.begin(115200);

  // Initialize I2C with custom pins (SDA=GPIO14, SCL=GPIO12)
  Wire.begin(SDA_PIN, SCL_PIN);

  // Initialize OLED
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;);
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(F("Connecting to WiFi..."));
  display.display();

  // Connect to WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected");
  Serial.println(WiFi.localIP());

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("WiFi connected!"));
  display.println(WiFi.localIP());
  display.display();
  delay(1000);

  // Initialize NTP
  timeClient.begin();
  timeClient.update();

  Serial.println("NTP synchronized");

  // Configure HTTPS server with mutual TLS (using EC certs)
  server.setECCert(&serverCertList, BR_KEYTYPE_EC, &serverPrivKey);
  server.setClientTrustAnchor(&caCertList);

  // Start HTTPS server
  server.begin();
  Serial.println("HTTPS server started on port 443");
}

void handleClient(BearSSL::WiFiClientSecure &client) {
  // Wait for data
  unsigned long timeout = millis() + 2000;
  while (!client.available() && millis() < timeout) {
    delay(1);
  }

  if (!client.available()) {
    client.stop();
    return;
  }

  // Read request line
  String request = client.readStringUntil('\r');
  client.readStringUntil('\n');

  // Consume headers
  while (client.available()) {
    String line = client.readStringUntil('\n');
    if (line.length() <= 1) break;
  }

  // Only handle GET /
  if (request.startsWith("GET / ") || request.startsWith("GET /index") || request == "GET /") {
    unsigned long epochTime = timeClient.getEpochTime();
    unsigned long expiresAt = ((epochTime / 30) + 1) * 30;

    String json = "{\"code\":\"" + currentCode + "\",\"expires_at\":" + String(expiresAt) + "}";

    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.print("Content-Length: ");
    client.println(json.length());
    client.println();
    client.print(json);
  } else {
    client.println("HTTP/1.1 404 Not Found");
    client.println("Connection: close");
    client.println();
  }

  client.stop();
}

unsigned long lastDisplayUpdate = 0;

void loop() {
  // Handle HTTPS clients - check frequently
  BearSSL::WiFiClientSecure client = server.accept();
  if (client) {
    handleClient(client);
  }

  yield();  // Let WiFi stack process

  timeClient.update();

  unsigned long epochTime = timeClient.getEpochTime();
  unsigned long timeStep = epochTime / 30;

  // Only regenerate code when time step changes
  if (timeStep != lastCodeTime) {
    lastCodeTime = timeStep;
    currentCode = getTotp(epochTime);
    Serial.print("New code: ");
    Serial.println(currentCode);
  }

  // Update display only every 250ms to reduce CPU load
  if (millis() - lastDisplayUpdate >= 250) {
    lastDisplayUpdate = millis();

    // Calculate seconds remaining in current period
    int secondsRemaining = 30 - (epochTime % 30);

    // Update display
    display.clearDisplay();

    // Header
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println(OTP_HEADER);

    // Horizontal line
    display.drawLine(0, 24, 127, 24, SSD1306_WHITE);

    // OTP Code - large font, centered for 6 digits
    display.setTextSize(3);
    display.setCursor(10, 30);
    display.print(currentCode);

    // Time remaining - progress bar
    display.setTextSize(1);
    display.setCursor(100, 56);
    display.print(secondsRemaining);
    display.print("s");

    // Progress bar
    int barWidth = map(secondsRemaining, 0, 30, 0, 90);
    display.drawRect(0, 56, 92, 8, SSD1306_WHITE);
    display.fillRect(1, 57, barWidth, 6, SSD1306_WHITE);

    display.display();
  }

  yield();  // Let WiFi stack process
}
