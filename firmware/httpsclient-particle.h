#pragma once

#include "application.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "matrixsslApi.h"

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
	
typedef void (*callback_function)(unsigned char*, int);
callback_function g_callback_func;

int httpsclientSetup(const char * host, const char * path, callback_function pFunc);
int httpsClientConnection(unsigned char * requestContent, uint32 msg_len,
			  const char * msg);
void httpsclientCleanUp();
void httpsclientSetPath(const char * path);

#ifdef __cplusplus
}
#endif
