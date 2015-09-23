#include "httpsclient-particle.h"
#include "matrixsslApi.h"

#define TIMEAPI_IP_INT_TUPLE 54,243,60,28

const bool g_https_trace = true;
static int anomalyLed = D7;
static int heartbeatLed = D7;
const char g_ip_str [] = "54.243.60.28";
const char host [] = "www.timeapi.org";
const char endpoint [] = "/utc/now/";
static IPAddress g_ip = IPAddress(TIMEAPI_IP_INT_TUPLE);
const int g_port = 443;
static unsigned int freemem;
bool g_https_complete;
uint32 g_bytes_received;
TCPClient client;

// Replace XXXX..XX with base64 encoding of glowfi.sh username:password
unsigned char httpRequestContent[] = "GET %s HTTP/1.0\r\n"
  "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
  "Authorization: Basic XXXXXXXXXX\r\n"
  "Host: www.timeapi.org\r\n"
  "Accept: */*\r\n"
  "Content-Type: applcation/json\r\n\r\n";

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
