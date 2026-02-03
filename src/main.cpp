#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <sha1.h>
#include "secrets.h"
#include "server_certs.h"
#include <Fonts/FreeMono9pt7b.h>
#include <Fonts/FreeMonoBold18pt7b.h>


// OLED display settings
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define HEADER_HEIGHT 16
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

unsigned long lastNtpSyncMillis = 0;
const unsigned long ntpSyncInterval = 1000 * 60 * 60; // Sync with NTP every hour

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
  WiFi.hostname(HOSTNAME);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected");
  Serial.println(WiFi.localIP());

  if (MDNS.begin(HOSTNAME)) {
    Serial.println("mDNS responder started");
    MDNS.addService("https", "tcp", 443);
    display.setCursor(0, 16);
    display.printf("Hostname: %s", HOSTNAME);
  } else {
    Serial.printf("mDNS responder failed to register hostname %s", HOSTNAME);
    display.setCursor(0, 16);
    display.printf("mDSN Failed: %s", HOSTNAME);
  }
  display.display();

  display.setCursor(0, 32);
  display.printf("IP: %s", WiFi.localIP().toString());
  display.setCursor(0, 48);
  display.println(F("WiFi connected!"));
  display.display();
  delay(5000);

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
  // Keep mDNS service running (responds to MDSN requests)
  MDNS.update();

  // Handle HTTPS clients - check frequently
  BearSSL::WiFiClientSecure client = server.accept();
  if (client) {
    handleClient(client);
  }

  yield();  // Let WiFi stack process

  // Keep mDNS service running (responds to MDSN requests)
  MDNS.update();

  unsigned long currentMillis = millis();
  if (currentMillis - lastNtpSyncMillis > ntpSyncInterval) {
      timeClient.update();
      lastNtpSyncMillis = currentMillis;
  }

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

    display.setFont(&FreeMono9pt7b);

    // Header - centered
    int16_t x1, y1;
    uint16_t textWidth, textHeight;
    display.getTextBounds(OTP_HEADER, 0, 0, &x1, &y1, &textWidth, &textHeight);
    display.setCursor((SCREEN_WIDTH - textWidth) / 2, textHeight + ((HEADER_HEIGHT - textHeight) / 2));
    display.println(OTP_HEADER);
    display.setFont();

    // Horizontal line
    display.drawLine(0, HEADER_HEIGHT + 2, 127, HEADER_HEIGHT + 2, SSD1306_WHITE);

    // OTP Code - large font, centered for 6 digits
    display.setTextSize(1);
    display.setFont(&FreeMonoBold18pt7b);
    display.setCursor(0, 47);
    display.print(currentCode);
    display.setFont();

    // Time remaining - progress bar
    display.setTextSize(1);
    display.setCursor(110, 56);
    display.print(secondsRemaining);
    display.print("s");

    // Progress bar
    int barWidth = map(secondsRemaining, 0, 30, 0, 100);
    display.drawRect(0, 56, 102, 8, SSD1306_WHITE);
    display.fillRect(1, 57, barWidth, 6, SSD1306_WHITE);

    display.display();
  }

  yield();  // Let WiFi stack process
}
