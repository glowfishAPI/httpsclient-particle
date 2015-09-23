#include "httpsclient-particle.h"
#include "matrixssl/matrixsslApi.h"

#define GLOWFISH_IP_INT_TUPLE 130,211,173,55

const bool g_https_trace = true;
static int anomalyLed = D7;
static int heartbeatLed = D7;
const char g_ip_str [] = "130.211.173.55";
const char host [] = "api.glowfi.sh";
const char endpoint [] = "/v1/anomaly_detect/reset_model/";
static IPAddress g_ip = IPAddress(GLOWFISH_IP_INT_TUPLE);
const int g_port = 443;
static unsigned int freemem;
bool g_https_complete;
uint32 g_bytes_received;
TCPClient client;
// Replace XXXX...XXX with base64 encoding if your gf username:password
unsigned char httpRequestContent[] = "POST %s HTTP/1.0\r\n"
  "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
  "Authorization: Basic XXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
  "Host: api.glowfi.sh\r\n"
  "Accept: */*\r\n"
  "Content-Type: applcation/json\r\n"
  "Content-Length: 39\r\n\r\n"
  "{\"data_set\": {\"temperature555\": [5.1]}}";

void setup() {
  pinMode(anomalyLed, OUTPUT);
  httpsclientSetup(g_ip_str, host, endpoint);
}

unsigned int nextTime = 0;    // Next time to contact the server
int g_connected;
void loop() {
  if (nextTime > millis()) return;
  g_connected = client.connect(g_ip, g_port);
  if (!g_connected) {
    client.stop();
    // If TCP Client can't connect to host, exit here.
    return;
  }
  g_https_complete = false;
  g_bytes_received = 0;
#ifdef LOGGING_DEBUG
  freemem = System.freeMemory();
  Serial.print("free memory: ");
  Serial.println(freemem);
#endif
  int32 rc;
  if ((rc = httpsClientConnection(httpRequestContent) < 0)) {
    // TODO: When massive FAIL
    httpsclientCleanUp();
    digitalWrite(anomalyLed, HIGH);
    delay(500);
    digitalWrite(anomalyLed, LOW);
    delay(500);
    digitalWrite(anomalyLed, HIGH);
    delay(500);
    digitalWrite(anomalyLed, LOW);
  } else {
    digitalWrite(heartbeatLed, HIGH);
    delay(250);
    digitalWrite(heartbeatLed, LOW);
  }
  client.stop();
  nextTime = millis() + 5000;
}
