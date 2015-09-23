#include "matrixsslApi.h"
#include "application.h"
#define HTTPS_COMPLETE 1
#define HTTPS_ERROR -1
#define ALLOW_ANON_CONNECTIONS 1
#define LOGGING_DEBUG

#define USE_RSA_CIPHER_SUITE
#define ID_RSA

extern TCPClient client;
extern bool g_https_complete;
extern uint32 g_bytes_received;
extern const bool g_https_trace;

int httpsclientSetup(const char * g_ip_str, const char * host,
		     const char * path);
int httpsClientConnection(unsigned char * requestContent);
void httpsclientCleanUp();
