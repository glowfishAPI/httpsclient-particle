static int anomalyLed = D7;
static int heartbeatLed = D7;

const bool g_https_trace = true;  // This controls debug info print to Serial
const char host [] = "www.timeapi.org";
const char endpoint [] = "/utc/now/";
const int g_port = 443; // DoNOT change this unless you know what's up
static unsigned int freemem;
bool g_https_complete;
uint32 g_bytes_received;

TCPClient client;

unsigned char httpRequestContent[] = "GET %s HTTP/1.0\r\n"
  "User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
  "Host: www.timeapi.org\r\n"
  "Accept: */*\r\n"
  "Content-Type: applcation/json\r\n"
  "Content-Length: %d\r\n\r\n%s";

void setup() {
  if (g_https_trace) {
    Serial.begin(9600);
  }
  pinMode(anomalyLed, OUTPUT);
  httpsclientSetup(host, endpoint);
}

unsigned int nextTime = 0;    // Next time to contact the server
int g_connected;
void loop() {
  if (nextTime > millis()) return;
  g_connected = client.connect(host, g_port);
  if (!g_connected) {
    client.stop();
    // If TCP Client can't connect to host, exit here.
    return;
  }
  g_https_complete = false;
  g_bytes_received = 0;
  if (g_https_trace) {
    freemem = System.freeMemory();
    Serial.print("free memory: ");
    Serial.println(freemem);
  }
  int32 rc;
  if ((rc = httpsClientConnection(httpRequestContent, 0, NULL) < 0)) {
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
