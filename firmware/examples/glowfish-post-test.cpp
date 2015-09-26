#define GLOWFISH_IP_INT_TUPLE 130,211,173,55

const bool g_https_trace = true;
static int anomalyLed = D7;
static int heartbeatLed = D7;
const char g_ip_str [] = "130.211.173.55";
const char host [] = "api.glowfi.sh";
const char ad_endpoint [] = "/v1/anomaly_detect/";
const char se_endpoint [] = "/v1/signal_extract/";
static IPAddress g_ip = IPAddress(GLOWFISH_IP_INT_TUPLE);
const int g_port = 443;
static unsigned int freemem;
bool g_https_complete;
uint32 g_bytes_received;
TCPClient client;

#define GF_JSON_SIZE 300
// Replace XXXX...XXX with base64 encoding if your gf username:password
unsigned char httpRequestContent[] = "POST %s HTTP/1.0\r\n"
  "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
  "Authorization: Basic XXXX...XXX\r\n"
  "Host: api.glowfi.sh\r\n"
  "Accept: */*\r\n"
  "Content-Type: applcation/json\r\n"
  "Content-Length: %d\r\n\r\n%s";

void setup() {
  pinMode(anomalyLed, OUTPUT);
  httpsclientSetup(g_ip_str, host, se_endpoint);
}

unsigned int nextTime = 0;    // Next time to contact the server
int g_connected;
void loop() {
  unsigned int t = millis();
  if (nextTime > t) return;
  StaticJsonBuffer<GF_JSON_SIZE> glowfishJson;
  JsonObject& top = glowfishJson.createObject();
  JsonObject& data_set = top.createNestedObject("data_set");
  // TODO: I don't quite understand how much memory needs to get allocated
  //JsonObject& time = top.createNestedArray("time");
  JsonArray& freememJ = data_set.createNestedArray("freemem");
  freememJ.add(System.freeMemory());
  JsonArray& timeup = data_set.createNestedArray("timeup");
  timeup.add(t/1000);
  char jsonBuf[GF_JSON_SIZE];
  size_t bufsize = top.printTo(jsonBuf, sizeof(jsonBuf));
  
  g_connected = client.connect(g_ip, g_port);
  if (!g_connected) {
    client.stop();
    // If TCP Client can't connect to host, exit here.
    return;
  }
  g_https_complete = false;
  g_bytes_received = 0;
#ifdef LOGGING_DEBUG
  Serial.print("free memory: ");
  Serial.println(freemem);
#endif
  int rc;
  httpsclientSetPath(se_endpoint);
  if ((rc = httpsClientConnection(httpRequestContent, bufsize, jsonBuf)) < 0) {
    // TODO: When massive FAIL
#ifdef LOGGING_DEBUG
    Serial.print("httpsClientConnection Returned ");
    Serial.println(rc);
#endif
    httpsclientCleanUp();
    digitalWrite(anomalyLed, HIGH);
    delay(500);
    digitalWrite(anomalyLed, LOW);
    delay(500);
    digitalWrite(anomalyLed, HIGH);
    delay(500);
    digitalWrite(anomalyLed, LOW);
    return;
  } else {
    digitalWrite(heartbeatLed, HIGH);
    delay(250);
    digitalWrite(heartbeatLed, LOW);
  }
  client.stop();
  nextTime = millis() + 5000;
}
