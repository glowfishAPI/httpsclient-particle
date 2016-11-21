/*
  This file follows client.c from matrixSSL-3.7.2b closely to make a post/
  get using https. It is also inspired by the httpclient library available
  on github for the particle photon
  (https://github.com/nmattisson/HttpClient)
 */
// WARNING WARNING WARNING:
// This is for test purposes only, the RSA keys included in header files are SAMPLE
// If you use these keys in production, an attacker can de-crypt your data, and look
// at it, and you might as well have been using http without https.

#include "httpsclient-particle.h"
#ifdef ID_RSA
#include "2048_RSA.h"
#include "2048_RSA_KEY.h"
#include "ALL_RSA_CAS.h"
#endif

uint32_t freemem;

int32 rc, CAstreamLen, i;
sslKeys_t *keys;
sslSessionId_t *sid;
//struct g_sslstats stats;
unsigned char *CAstream;
tlsExtension_t *extension;
int32 len, sessionFlag, extLen;
ssl_t *ssl;
unsigned char *g_buf, *ext;
sslSessOpts_t options;

const int g_key_len = 2048;
uint32 g_cipher[1] = {60};
const int g_ciphers = 1;
// INFO: Turns out it's a huge deal to make this >= 3000.
//       The TCPClient really does take >2000ms to give us a packet for some reason?!!
const uint16_t TIMEOUT = 20000;
unsigned char * g_httpRequestHdr;
const char end_header[] = "\r\n\r\n";

// TODO: Complete HACK, is it necessary to know how many bytes to expect from
//       the server?
uint32 g_bytes_requested = 100000;

#ifdef ID_RSA
int32 loadRsaKeys(uint32 key_len, sslKeys_t *keys,
			 unsigned char *CAstream, int32 CAstreamLen) {
  int32 rc;
// INFO: 2048 is just good enough for now
  if (g_https_trace) Serial.println("Using 2048 bit RSA private key");
  rc = matrixSslLoadRsaKeysMem(keys, RSA2048, sizeof(RSA2048), RSA2048KEY,
			       sizeof(RSA2048KEY), CAstream, CAstreamLen);
  if (rc < 0) {
    if (g_https_trace) _psTrace("No certificate material loaded.  Exiting");
    if (CAstream) {
      psFree(CAstream, NULL);
    }
    matrixSslDeleteKeys(keys);
    matrixSslClose();
  }

  return rc;
}
#endif

const char * g_host;
const char * g_path;

void httpsclientSetPath(const char * path) {
  g_path = path;
}

void (*g_weatherCallback_func)(unsigned char*, int);

int httpsclientSetup(const char * host, const char * path, void (*pFunc)(unsigned char*, int)) {
  int rc;
  g_host = host;
  g_path = path;
  g_weatherCallback_func = pFunc;
  if ((rc = matrixSslOpen()) < 0) {
    if (g_https_trace) _psTrace("MatrixSSL library init failure.");
    return rc;
  }

  if ((rc = matrixSslNewKeys(&keys, NULL)) < 0) {
    if (g_https_trace) Serial.println("MatrixSSL library key init failure.");
    return HTTPS_ERROR;
  }
#ifndef USE_ONLY_PSK_CIPHER_SUITE
  /*
    In-memory based keys
    Build the CA list first for potential client auth usage
  */
  CAstreamLen = 0;
#ifdef USE_RSA_CIPHER_SUITE
  CAstreamLen += sizeof(RSACAS);
#ifdef USE_ECC_CIPHER_SUITE
  CAstreamLen += sizeof(ECDHRSACAS);
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
  CAstreamLen += sizeof(ECCAS);
#endif
  if (CAstreamLen > 0) {
    CAstream = (unsigned char *) psMalloc(NULL, CAstreamLen);
  } else {
    CAstream = NULL;
  }
  CAstreamLen = 0;
#ifdef USE_RSA_CIPHER_SUITE
  memcpy(CAstream, RSACAS, sizeof(RSACAS));
  CAstreamLen += sizeof(RSACAS);
#ifdef USE_ECC_CIPHER_SUITE
  memcpy(CAstream + CAstreamLen, ECDHRSACAS, sizeof(ECDHRSACAS));
  CAstreamLen += sizeof(ECDHRSACAS);
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
  memcpy(CAstream + CAstreamLen, ECCAS, sizeof(ECCAS));
  CAstreamLen += sizeof(ECCAS);
#endif


#ifdef ID_RSA
  rc = loadRsaKeys(g_key_len, keys, CAstream, CAstreamLen);
  if (rc < 0) {
    if (g_https_trace) {
      Serial.print("Keys didn't load!: loadRsaKeys returned: ");
      Serial.println(rc);
    }
    return rc;
  }
  if (g_https_trace) _psTrace("Keys Loaded");
#endif

  if (CAstream) psFree(CAstream, NULL);

#endif /* USE_ONLY_PSK_CIPHER_SUITE */

  matrixSslNewSessionId(&sid, NULL);
  if (g_https_trace) Serial.println("New Session key!: ");
  sessionFlag = SSL_FLAGS_TLS_1_2;
}

static int32 httpWriteRequest(uint32 msg_length, const char * message) {
  unsigned char   *buf;
  int32	available, requested;

  requested = strlen((char *)g_httpRequestHdr) + strlen(g_path) + 1 + msg_length + 10;
  if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0) {
    return PS_MEM_FAIL;
  }
  requested = min(requested, available);
  snprintf((char *)buf, requested, (char *)g_httpRequestHdr, g_path,
	   msg_length, message);
  if (g_https_trace) _psTrace((char*)buf);
  
  if (matrixSslEncodeWritebuf(ssl, strlen((char *)buf)) < 0) {
    return PS_MEM_FAIL;
  }
  return MATRIXSSL_REQUEST_SEND;

}

static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE

  if (g_https_trace) {
    Serial.print("certCb invoked: "); Serial.println(alert);
  }
  /* Did we even find a CA that issued the certificate? */
  if (alert == SSL_ALERT_UNKNOWN_CA) {
    /* Example to allow anonymous connections based on a define */
    if (ALLOW_ANON_CONNECTIONS) {
      if (g_https_trace)
	Serial.println("Allowing anonymous connection for:");
      //cert->subject.commonName holds the value?
      return SSL_ALLOW_ANON_CONNECTION;
    }
    if (g_https_trace)
      Serial.println("ERROR: No matching CA found.  Terminating connection");
  }
  psX509Cert_t    *next;

  /* If the expectedName passed to matrixSslNewClientSession does not
    match any of the server subject name or subjAltNames, we will have
    the alert below.
    For security, the expected name (typically a domain name) _must_
    match one of the certificate subject names, or the connection
    should not continue.
    The default MatrixSSL certificates use localhost and 127.0.0.1 as
    the subjects, so unless the server IP matches one of those, this
    alert will happen.
    To temporarily disable the subjet name validation, NULL can be passed
    as expectedName to matrixNewClientSession.
  */
  if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN) {
    //ssl->expectedName not found in cert subject names
    if (g_https_trace)
      Serial.println("ERROR: expectedName not found in cert subject names");
  }

  if (alert == SSL_ALERT_CERTIFICATE_EXPIRED) {
#ifdef POSIX

    if (g_https_trace)
      Serial.println("ERROR: A cert did not fall within the "
		     "notBefore/notAfter window");

#else
    if (g_https_trace)
      Serial.println("WARNING: Certificate date window validation not "
		     "implemented");
    alert = 0;
#endif
  }

  if (alert == SSL_ALERT_ILLEGAL_PARAMETER) {
    if (g_https_trace)
      Serial.println("ERROR: Found correct CA but X.509 extension details are "
		     "wrong");
  }

  /* Key usage related problems on chain */
  for (next = cert; next != NULL; next = next->next) {
    if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION) {
      if (next->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
	if (g_https_trace)
	  Serial.println("CA keyUsage extension doesn't allow cert signing");
      }
      if (next->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
	if (g_https_trace)
	  Serial.println("Cert extendedKeyUsage extension doesn't allow TLS");
      }
    }
  }

  if (alert == SSL_ALERT_BAD_CERTIFICATE) {
    /* Should never let a connection happen if this is set.  There was
       either a problem in the presented chain or in the final CA test */
    if (g_https_trace)
      Serial.println("ERROR: Problem in certificate validation.  Exiting.");
  }


  if (alert == 0) {
    // Passes test: cert->subject.commonName
    if (g_https_trace) Serial.println("SUCCESS: Validated!");
  }
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
  return alert;
}

static int32 extensionCb(ssl_t *ssl, unsigned short extType,
			 unsigned short extLen, void *e) {
  unsigned char   *c;
  short len;
  char proto[128];

  c = (unsigned char*)e;

  if (extType == EXT_ALPN) {
    memset(proto, 0x0, 128);
    /* two byte proto list len, one byte proto len, then proto */
    c += 2; /* Skip proto list len */
    len = *c; c++;
    memcpy(proto, c, len);
    if (g_https_trace) {
      Serial.print("Server agreed to use ");
      Serial.println(proto);
    }
  }
  return PS_SUCCESS;
}

static int32 TCPRead (int len) {
  unsigned int bufferPosition = 0;
  char c;
  unsigned long lastRead = millis();
  bool error = false;
  bool timeout = false;

  do {
    while (client.available()) {
      c = client.read();
      // if (g_https_trace) {
      // 	if (bufferPosition == 0) Serial.println("TCP Receiving ...");
      // 	if ((c < 32) || (c > 126)) Serial.print('.');
      // 	else Serial.print(c);
      // 	if (bufferPosition % 80 == 0) Serial.println();
      // }
      lastRead = millis();
      if (c == -1) {
	error = true;
	if (g_https_trace)
	  Serial.println("HttpClient>\tError: No data available.");
	break;
      }

      // Check that received character fits in buffer before storing.
      if (bufferPosition < len) {
	g_buf[bufferPosition++] = c;
      }
      if (bufferPosition == len) {
	return bufferPosition;
      }
    }

    if (g_https_trace) {
      _psTrace("HttpClient>\tDone before full len ");
      Serial.println(bufferPosition);
    }

    //  Check for timeout since last read
    timeout = millis() - lastRead > TIMEOUT;
    if (!error && !timeout) {
      delay(200);
    }
  } while (client.connected() && !timeout && (bufferPosition == 0));
  return bufferPosition;
}

int httpsClientConnection(unsigned char * requestContent, uint32 msg_len,
			  const char * message) {
  int32 rc, len, transferred;
  g_httpRequestHdr = requestContent;

  memset(&options, 0x0, sizeof(sslSessOpts_t));
  options.versionFlag = sessionFlag;
  options.userPtr = keys;
  matrixSslNewHelloExtension(&extension, NULL);
  matrixSslCreateSNIext(NULL, (unsigned char*)g_host, (uint32)strlen(g_host),
			&ext, &extLen);
  matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
  // TOOD: Dynamic memory allocation, possible memory leak
  psFree(ext, NULL);

  rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers, certCb,
				 NULL, extension, extensionCb, &options);

  if (g_https_trace) {
    Serial.print("matrixSslNewClientSession:");
    Serial.println(rc);
  }

  matrixSslDeleteHelloExtension(extension);

  if (rc != MATRIXSSL_REQUEST_SEND) {
    if (g_https_trace)
      Serial.println("New Client Session Failed: Exiting\n");
    return HTTPS_ERROR;
  }

  if (g_https_trace) {
    freemem = System.freeMemory();
    Serial.print("free memory 3: ");
    Serial.println(freemem);
  }

 WRITE_MORE:
  while ((len = matrixSslGetOutdata(ssl, &g_buf)) > 0) {
    transferred = client.write(g_buf, len);
    client.flush();
    
    if (transferred <= 0) {
      goto L_CLOSE_ERR;
    }
    else {
      /* Indicate that we've written > 0 bytes of data */
      if (g_https_trace) {
	Serial.print("Bytes sent Successfully?!: ");Serial.println(len);
      }
      if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
	goto L_CLOSE_ERR;
      }
      if (g_https_trace) {
	Serial.print("matrixSslSentData: ");
	Serial.println(rc);
      }
      if (rc == MATRIXSSL_REQUEST_CLOSE) {
	// TOOD: Anything here?
	return MATRIXSSL_SUCCESS;
      }
      if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
	/* If we sent the Finished SSL message, initiate the HTTP req */
	/* (This occurs on a resumption handshake) */
	if (httpWriteRequest(msg_len, message) < 0) {
	  goto L_CLOSE_ERR;
	}
	goto WRITE_MORE;
      }
      /* SSL_REQUEST_SEND is handled by loop logic */
      if (g_https_trace)
	Serial.println("Sent Successfully?!, everything good");
    }
  }
 READ_MORE:
  if ((len = matrixSslGetReadbuf(ssl, &g_buf)) <= 0) {
    if (g_https_trace) {
      Serial.print("matrixSslGetReadbuf: ");
      Serial.println(len);
    }
    goto L_CLOSE_ERR;
  }
  if (g_https_trace) {
    Serial.print("matrixSslGetReadbuf: ");
    Serial.println(len);
  }
  if ((transferred = TCPRead(len)) < 0) {
    if (g_https_trace) {
      Serial.print("Received: ");
      Serial.println(transferred);
    }
    goto L_CLOSE_ERR;
  }
  if (g_https_trace) {
    Serial.print("Received: ");
    Serial.println(transferred);
  }
  if (transferred == 0) {
    goto L_CLOSE_ERR;
  }
  if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &g_buf,
				  (uint32*)&len)) < 0) {
    goto L_CLOSE_ERR;
  }
  if (g_https_trace) {
    Serial.print("matrixSslReceivedData: Tx: ");
    Serial.print((int32) transferred);
    Serial.print(" Len: "); Serial.print(len);
    Serial.print(" rc: "); Serial.println(rc);
  }

 PROCESS_MORE:
  switch (rc) {
  case MATRIXSSL_HANDSHAKE_COMPLETE:
#ifdef REHANDSHAKE_TEST
    /*
      Test rehandshake capabilities of server.  If a successful
      session resmption rehandshake occurs, this client will be last to
      send handshake data and MATRIXSSL_HANDSHAKE_COMPLETE will hit on
      the WRITE_MORE handler and httpWriteRequest will occur there.

      NOTE: If the server doesn't support session resumption it is
      possible to fall into an endless rehandshake loop
    */
    if (matrixSslEncodeRehandshake(ssl, NULL, NULL, 0,
				   g_cipher, g_ciphers) < 0) {
      goto L_CLOSE_ERR;
    }
#else
    /* We got the Finished SSL message, initiate the HTTP req */
    if (httpWriteRequest(msg_len, message) < 0) {
      goto L_CLOSE_ERR;
    }
#endif
    goto WRITE_MORE;
  case MATRIXSSL_APP_DATA:
  case MATRIXSSL_APP_DATA_COMPRESSED:
    g_bytes_received += len;
    (*g_weatherCallback_func)(g_buf,len);
    if (g_https_trace) {
      for (int i = 0 ; i < len; i++) {
	Serial.print((char)g_buf[i]);
      }
      Serial.println();
    }
    if (!g_https_complete) {
      if (strstr((const char *) g_buf, end_header)) {
	g_https_complete = true;
      }
    }
    rc = matrixSslProcessedData(ssl, &g_buf, (uint32*)&len);
    if (g_https_trace) {
      Serial.print("matrixSslProcessedData: ");
      Serial.println(rc);
    }
    if (rc < 0) {
      goto L_CLOSE_ERR;
    }
    if (g_bytes_requested > 0) {
      if (g_bytes_received >= g_bytes_requested) {
	/* We've received all that was requested, so close */
	if (g_https_trace)
	  Serial.println("Stopping connection for a stupid reason");
	return MATRIXSSL_SUCCESS;
      }
      if (rc == 0) {
	/* We processed a partial HTTP message */
	goto READ_MORE;
      }
    }
    goto PROCESS_MORE;
  case MATRIXSSL_REQUEST_SEND:
    goto WRITE_MORE;
  case MATRIXSSL_REQUEST_RECV:
    goto READ_MORE;
  case MATRIXSSL_RECEIVED_ALERT:
    /* The first byte of the buffer is the level */
    /* The second byte is the description */
    if (*g_buf == SSL_ALERT_LEVEL_FATAL) {
      if (g_https_trace) Serial.println("Fatal alert: %d, closing connection.");
      goto L_CLOSE_ERR;
    }
    /* Closure alert is normal (and best) way to close */
    if (*(g_buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
      if (g_https_trace) Serial.println("Gentle Close");
      // TODO: Do something with this whole parsing stuff
      return MATRIXSSL_SUCCESS;
    }
    if (g_https_trace) Serial.println("Warning alert");
    if ((rc = matrixSslProcessedData(ssl, &g_buf, (uint32*)&len)) == 0) {
      /* No more data in buffer. Might as well read for more. */
      if (g_https_trace) Serial.println("Reading more ...");
      goto READ_MORE;
    }
    if (g_https_trace) Serial.println("rc: %d, Processing more ..");
    goto PROCESS_MORE;
  default:
    /* If rc <= 0 we fall here */
    goto L_CLOSE_ERR;
  }
 L_CLOSE_ERR:
  if (!g_https_complete) {
    if (g_https_trace) Serial.println("FAIL: No HTTP Response");
  } else {
    if (g_https_trace) Serial.println("Received something");
  }
  matrixSslDeleteSession(ssl);
  return MATRIXSSL_ERROR;
}

void httpsclientCleanUp() {
  matrixSslDeleteSessionId(sid);
  matrixSslDeleteKeys(keys);
  matrixSslClose();
}
