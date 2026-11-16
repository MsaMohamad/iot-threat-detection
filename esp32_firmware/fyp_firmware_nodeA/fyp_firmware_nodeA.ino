#include <WiFi.h>
#include <WebServer.h>
#include <lwip/sockets.h>
#include <PubSubClient.h>


const char* ssid = "YOUR_WIFI_SSID";          // <-- set your Wi-Fi SSID
const char* password = "YOUR_WIFI_PASSWORD";  // <-- set your Wi-Fi password
const char* mqtt_server = "192.168.0.101";

// ===== Static IP (prevents the IP changing under DHCP) =====
IPAddress local_IP(192, 168, 0, 136);
IPAddress gateway(192, 168, 0, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress primaryDNS(192, 168, 0, 1);

WiFiClient espClient;
PubSubClient client(espClient);
WebServer server(80);

int raw_sock;
unsigned long lastPublish = 0;
unsigned long lastPortWindow60 = 0;  // timer reset tetingkap 60s

// Packet-level counters
unsigned int synCount = 0;
unsigned int ackCount = 0;
unsigned int rstCount = 0;
unsigned int finCount = 0;
unsigned int totalPackets = 0;
unsigned long totalBytes = 0;

// Port diversity tracking (3s window - for ML)
static uint8_t portSeen[8192];
unsigned int uniquePortCount = 0;

// Slow-scan tracking (60s sliding window - catches slow scans)
static uint8_t portSeen60[8192];
unsigned int uniquePortCount60 = 0;

// Login attempt tracking
unsigned int loginAttempts = 0;
unsigned int failedLogins = 0;

// ===== NEW: Source IP tracking =====
uint32_t lastSourceIP = 0;  // source IP from the last SYN packet in this window

const char* validUser = "admin";
const char* validPass = "CHANGE_ME";          // <-- demo honeypot login (brute-force test)

void setPortSeen(uint16_t port) {
  int byteIndex = port / 8;
  int bitIndex = port % 8;
  if (!(portSeen[byteIndex] & (1 << bitIndex))) {
    portSeen[byteIndex] |= (1 << bitIndex);
    uniquePortCount++;
  }
}

void resetPortTracking() {
  memset(portSeen, 0, sizeof(portSeen));
  uniquePortCount = 0;
}

void setPortSeen60(uint16_t port) {
  int byteIndex = port / 8;
  int bitIndex = port % 8;
  if (!(portSeen60[byteIndex] & (1 << bitIndex))) {
    portSeen60[byteIndex] |= (1 << bitIndex);
    uniquePortCount60++;
  }
}

// ===== NEW: Convert uint32 IP to string format "x.x.x.x" =====
String ipToString(uint32_t ip) {
  return String((ip >> 24) & 0xFF) + "." +
         String((ip >> 16) & 0xFF) + "." +
         String((ip >> 8) & 0xFF) + "." +
         String(ip & 0xFF);
}

void handleRoot() {
  String html = "<html><body>";
  html += "<h2>IoT Camera Admin Login</h2>";
  html += "<form method='POST' action='/login'>";
  html += "Username: <input type='text' name='username'><br>";
  html += "Password: <input type='password' name='password'><br>";
  html += "<input type='submit' value='Login'>";
  html += "</form></body></html>";
  server.send(200, "text/html", html);
}

void handleLogin() {
  loginAttempts++;

  // ===== NEW: Track client IPs that attempt to log in =====
  IPAddress clientIP = server.client().remoteIP();
  lastSourceIP = ((uint32_t)clientIP[0] << 24) | ((uint32_t)clientIP[1] << 16) |
                 ((uint32_t)clientIP[2] << 8) | clientIP[3];

  String user = server.arg("username");
  String pass = server.arg("password");

  if (user == validUser && pass == validPass) {
    server.send(200, "text/plain", "Login successful!");
  } else {
    failedLogins++;
    server.send(200, "text/plain", "Login failed - invalid credentials");
  }
}

void setup_wifi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(ssid);
  if (!WiFi.config(local_IP, gateway, subnet, primaryDNS)) {
    Serial.println("Static IP config FAILED");
  }
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi Connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());
}

void reconnect_mqtt() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT...");
    if (client.connect("ESP32_FYP_v5")) {
      Serial.println("connected!");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      delay(2000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  setup_wifi();

  server.on("/", handleRoot);
  server.on("/login", HTTP_POST, handleLogin);
  server.begin();
  Serial.println("Web server + login form started on port 80");

  raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (raw_sock < 0) {
    Serial.println("FAILED to create raw socket!");
    while(1) delay(1000);
  }
  Serial.println("Raw socket ready. Monitoring TCP packets...");

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 10000;
  setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  resetPortTracking();
  lastPortWindow60 = millis();
  client.setServer(mqtt_server, 1883);
  client.setBufferSize(512);
}

void loop() {
  if (!client.connected()) {
    reconnect_mqtt();
  }
  client.loop();
  server.handleClient();

  uint8_t buffer[1500];
  int len = recv(raw_sock, buffer, sizeof(buffer), 0);

  if (len > 0) {
    totalPackets++;
    totalBytes += len;

    uint8_t ip_header_len = (buffer[0] & 0x0F) * 4;
    uint8_t tcp_flags = buffer[ip_header_len + 13];

    bool flag_fin = tcp_flags & 0x01;
    bool flag_syn = tcp_flags & 0x02;
    bool flag_rst = tcp_flags & 0x04;
    bool flag_ack = tcp_flags & 0x10;

    if (flag_syn) synCount++;
    if (flag_ack) ackCount++;
    if (flag_rst) rstCount++;
    if (flag_fin) finCount++;

    uint16_t dst_port = (buffer[ip_header_len + 2] << 8) | buffer[ip_header_len + 3];
    setPortSeen(dst_port);
    setPortSeen60(dst_port);

    // ===== NEW: Extract source IP from the IP header (byte offset 12-15) =====
    if (flag_syn) {
      uint32_t src_ip = ((uint32_t)buffer[12] << 24) | ((uint32_t)buffer[13] << 16) |
                         ((uint32_t)buffer[14] << 8) | buffer[15];
      lastSourceIP = src_ip;
    }
  }

  if (millis() - lastPublish > 3000) {
    lastPublish = millis();

    float duration_sec = 3.0;
    float pkts_per_sec = totalPackets / duration_sec;
    float bytes_per_sec = totalBytes / duration_sec;

    String sourceIPStr = ipToString(lastSourceIP);

    String payload = "{";
    payload += "\"device\":\"esp32_1\",";
    payload += "\"total_pkts\":" + String(totalPackets) + ",";
    payload += "\"total_bytes\":" + String(totalBytes) + ",";
    payload += "\"pkts_per_sec\":" + String(pkts_per_sec, 2) + ",";
    payload += "\"bytes_per_sec\":" + String(bytes_per_sec, 2) + ",";
    payload += "\"syn_count\":" + String(synCount) + ",";
    payload += "\"ack_count\":" + String(ackCount) + ",";
    payload += "\"rst_count\":" + String(rstCount) + ",";
    payload += "\"fin_count\":" + String(finCount) + ",";
    payload += "\"unique_dst_ports\":" + String(uniquePortCount) + ",";
    payload += "\"unique_ports_60s\":" + String(uniquePortCount60) + ",";
    payload += "\"login_attempts\":" + String(loginAttempts) + ",";
    payload += "\"failed_logins\":" + String(failedLogins) + ",";
    payload += "\"source_ip\":\"" + sourceIPStr + "\"";
    payload += "}";

    client.publish("iot/esp32_1/data", payload.c_str());
    Serial.println("Published: " + payload);

    synCount = 0;
    ackCount = 0;
    rstCount = 0;
    finCount = 0;
    totalPackets = 0;
    totalBytes = 0;
    loginAttempts = 0;
    failedLogins = 0;
    lastSourceIP = 0;
    resetPortTracking();
  }

  // Reset the 60s window for slow-scan detection
  if (millis() - lastPortWindow60 > 60000) {
    lastPortWindow60 = millis();
    memset(portSeen60, 0, sizeof(portSeen60));
    uniquePortCount60 = 0;
  }
}