/**
 *	@file    client.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Simple MatrixSSL blocking client example.
 */
/*
 *	Copyright (c) 2013-2015 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "app.h"
#ifndef WIN32
#include <unistd.h>
#else
#include "XGetopt.h"
#endif
#include "matrixssl/matrixsslApi.h"

#ifdef USE_CLIENT_SIDE_SSL

#ifdef WIN32
#pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#else
#warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#endif

/*
	If supporting client authentication, pick ONE identity to auto select a
	certificate	and private key that support desired algorithms.
*/
#define ID_RSA /* RSA Certificate and Key */
//#define ID_ECDH_ECDSA /* EC Certificate and Key */
//#define ID_ECDH_RSA /* EC Key with RSA signed certificate */

#define USE_HEADER_KEYS
#define ALLOW_ANON_CONNECTIONS	1

/*	If the algorithm type is supported, load a CA for it */
#ifdef USE_HEADER_KEYS
/* CAs */
#ifdef USE_RSA_CIPHER_SUITE
#include "sampleCerts/RSA/ALL_RSA_CAS.h"
#ifdef USE_ECC_CIPHER_SUITE
#include "sampleCerts/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
#include "sampleCerts/EC/ALL_EC_CAS.h"
#endif

/* Identity Certs and Keys for use with Client Authentication */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
#include "sampleCerts/RSA/1024_RSA.h"
#include "sampleCerts/RSA/1024_RSA_KEY.h"
#include "sampleCerts/RSA/2048_RSA.h"
#include "sampleCerts/RSA/2048_RSA_KEY.h"
#include "sampleCerts/RSA/4096_RSA.h"
#include "sampleCerts/RSA/4096_RSA_KEY.h"
#endif

#ifdef ID_ECDH_ECDSA
#define EXAMPLE_EC_KEYS
#include "sampleCerts/EC/384_EC.h"
#include "sampleCerts/EC/384_EC_KEY.h"
#endif

#ifdef ID_ECDH_RSA
#define EXAMPLE_ECDH_RSA_KEYS
#include "sampleCerts/ECDH_RSA/521_ECDH-RSA.h"
#include "sampleCerts/ECDH_RSA/521_ECDH-RSA_KEY.h"
#endif

/* File-based keys */
#else
/* CAs */
#ifdef USE_RSA_CIPHER_SUITE
static char rsaCAFile[] = "../sampleCerts/RSA/ALL_RSA_CAS.pem";
#ifdef USE_ECC_CIPHER_SUITE
static char ecdhRsaCAFile[] = "../sampleCerts/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
static char ecCAFile[] = "../sampleCerts/EC/ALL_EC_CAS.pem";
#endif

/* Identity Certs and Keys for use with Client Authentication */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "../sampleCerts/RSA/2048_RSA.pem";
static char rsaPrivkeyFile[] = "../sampleCerts/RSA/2048_RSA_KEY.pem";
#endif

#ifdef ID_ECDH_ECDSA
#define EXAMPLE_EC_KEYS
static char ecCertFile[] = "../sampleCerts/EC/521_EC.pem";
static char ecPrivkeyFile[] = "../sampleCerts/EC/521_EC_KEY.pem";
#endif

#ifdef ID_ECDH_RSA
#define EXAMPLE_ECDH_RSA_KEYS
static char ecdhRsaCertFile[] = "../sampleCerts/ECDH_RSA/521_ECDH-RSA.pem";
static char ecdhRsaPrivkeyFile[] = "../sampleCerts/ECDH_RSA/521_ECDH-RSA_KEY.pem";
#endif

#endif /* USE_HEADER_KEYS */

#ifdef USE_PSK_CIPHER_SUITE
#include "../sampleCerts/psk.h"
#endif

/* #define REHANDSHAKE_TEST */

/********************************** Globals ***********************************/
static unsigned char g_httpRequestHdr[] = "GET %s HTTP/1.0\r\n"
	"User-Agent: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
	"Accept: */*\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

static const char g_strver[][8] =
	{ "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2" };

static unsigned char g_matrixShutdownServer[] = "MATRIX_SHUTDOWN";

extern int opterr;
static char g_ip[16];
static char g_path[256];
static int g_port, g_new, g_resumed, g_ciphers, g_version, g_closeServer;
static int g_key_len, g_disableCertNameChk;
static uint32 g_cipher[16];
static int g_trace;

static uint32 g_bytes_requested;

struct g_sslstats {
	int		rbytes; 	/* Bytes read */
	int64	hstime;
	int64	datatime;
};

/********************************** Defines ***********************************/

/****************************** Local Functions *******************************/

static int32 httpWriteRequest(ssl_t *ssl);
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert);
static SOCKET socketConnect(char *ip, int32 port, int32 *err);
static void closeConn(ssl_t *ssl, SOCKET fd);
static int32 extensionCb(ssl_t *ssl, unsigned short extType,
						unsigned short extLen, void *e);

#ifdef USE_CRL
static int32 crlCb(psPool_t *pool, psX509Cert_t *CA, int append,
				char *url, uint32 urlLen);
#endif


/******************************************************************************/
/*
	Make a secure HTTP request to a defined IP and port
	Connection is made in blocking socket mode
	The connection is considered successful if the SSL/TLS session is
	negotiated successfully, a request is sent, and a HTTP response is received.
 */

static int32 httpsClientConnection(sslKeys_t *keys, sslSessionId_t *sid,
	struct g_sslstats *stats)
{
	tlsExtension_t	*extension;
	int32			rc, transferred, len, sessionFlag, extLen;
	ssl_t			*ssl;
	unsigned char	*buf, *ext;
	httpConn_t		cp;
	SOCKET			fd;
	psTime_t		t1, t2;
	sslSessOpts_t	options;
#ifdef USE_ALPN
	unsigned char	*alpn[MAX_PROTO_EXT];
	int32			alpnLen[MAX_PROTO_EXT];
#endif

	memset(&cp, 0x0, sizeof(httpConn_t));
	fd = socketConnect(g_ip, g_port, &rc);
	if (fd == INVALID_SOCKET || rc != PS_SUCCESS) {
		return PS_PLATFORM_FAIL;
	}

#ifdef SSL_FLAGS_SSLV3
	/* Corresponds to version 3.g_version */
	switch (g_version) {
	case 0:
		sessionFlag = SSL_FLAGS_SSLV3;
		break;
	case 1:
		sessionFlag = SSL_FLAGS_TLS_1_0;
		break;
	case 2:
		sessionFlag = SSL_FLAGS_TLS_1_1;
		break;
	case 3:
		sessionFlag = SSL_FLAGS_TLS_1_2;
		break;
	default:
		sessionFlag = SSL_FLAGS_TLS_1_0;
		break;
	}
#else
	/* MatrixSSL <= 3.4.2 don't support setting version on request */
	sessionFlag = 0;
#endif

	memset(&options, 0x0, sizeof(sslSessOpts_t));
	options.versionFlag = sessionFlag;
	options.userPtr = keys;
	//options.maxFragLen = 512;
	//options.truncHmac = PS_TRUE;
	//options.ticketResumption = PS_TRUE;
	//options.ecFlags |= SSL_OPT_SECP521R1;
	//options.ecFlags |= SSL_OPT_SECP384R1;
	//options.ecFlags |= SSL_OPT_SECP256R1;
	//options.ecFlags |= SSL_OPT_SECP224R1;
	//options.ecFlags |= SSL_OPT_SECP192R1;

	matrixSslNewHelloExtension(&extension, NULL);
	matrixSslCreateSNIext(NULL, (unsigned char*)g_ip, (uint32)strlen(g_ip),
		&ext, &extLen);
	matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
	psFree(ext, NULL);

#ifdef USE_ALPN
	/* Application Layer Protocol Negotiation */
	alpn[0] = psMalloc(NULL, strlen("http/1.0"));
	memcpy(alpn[0], "http/1.0", strlen("http/1.0"));
	alpnLen[0] = strlen("http/1.0");

	alpn[1] = psMalloc(NULL, strlen("http/1.1"));
	memcpy(alpn[1], "http/1.1", strlen("http/1.1"));
	alpnLen[1] = strlen("http/1.1");

	matrixSslCreateALPNext(NULL, 2, alpn, alpnLen, &ext, &extLen);
	matrixSslLoadHelloExtension(extension, ext, extLen, EXT_ALPN);
	psFree(alpn[0], NULL);
	psFree(alpn[1], NULL);
#endif

	/* We are passing the IP address of the server as the expected name */
	/* To skip certificate subject name tests, pass NULL instead of g_ip */
	if (g_disableCertNameChk == 0) {
		rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
			certCb, g_ip, extension, extensionCb, &options);
	} else {
		rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
			certCb, NULL, extension, extensionCb, &options);
	}

	matrixSslDeleteHelloExtension(extension);
	if (rc != MATRIXSSL_REQUEST_SEND) {
		_psTraceInt("New Client Session Failed: %d.  Exiting\n", rc);
		close(fd);
		return PS_ARG_FAIL;
	}
WRITE_MORE:
	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
	if (g_trace) psTraceBytes("SEND", buf, len);
		transferred = send(fd, buf, len, 0);
		if (transferred <= 0) {
			goto L_CLOSE_ERR;
		} else {
			/* Indicate that we've written > 0 bytes of data */
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				goto L_CLOSE_ERR;
			}
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				closeConn(ssl, fd);
				return MATRIXSSL_SUCCESS;
			}
			if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
				/* If we sent the Finished SSL message, initiate the HTTP req */
				/* (This occurs on a resumption handshake) */
				if (httpWriteRequest(ssl) < 0) {
					goto L_CLOSE_ERR;
				}
				goto WRITE_MORE;
			}
			/* SSL_REQUEST_SEND is handled by loop logic */
		}
	}

READ_MORE:
	if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
		goto L_CLOSE_ERR;
	}
	if ((transferred = recv(fd, buf, len, 0)) < 0) {
		goto L_CLOSE_ERR;
	}
	if (g_trace) psTraceBytes("RECV", buf, transferred);
	/*	If EOF, remote socket closed. But we haven't received the HTTP response
		so we consider it an error in the case of an HTTP client */
	if (transferred == 0) {
		goto L_CLOSE_ERR;
	}
	psGetTime(&t1, NULL);
	if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &buf,
									(uint32*)&len)) < 0) {
		psGetTime(&t2, NULL);
		if (ssl->hsState == SSL_HS_DONE) {
#ifdef USE_HIGHRES_TIME
			stats->datatime += psDiffUsecs(t1, t2);
#else
			stats->datatime += psDiffMsecs(t1, t2, NULL);
#endif
		} else {
#ifdef USE_HIGHRES_TIME
			stats->hstime += psDiffUsecs(t1, t2);
#else
			stats->hstime += psDiffMsecs(t1, t2, NULL);
#endif
		}
		goto L_CLOSE_ERR;
	}
	psGetTime(&t2, NULL);
	if (ssl->hsState == SSL_HS_DONE) {
#ifdef USE_HIGHRES_TIME
		stats->datatime += psDiffUsecs(t1, t2);
#else
		stats->datatime += psDiffMsecs(t1, t2, NULL);
#endif
	} else {
#ifdef USE_HIGHRES_TIME
		stats->hstime += psDiffUsecs(t1, t2);
#else
		stats->hstime += psDiffMsecs(t1, t2, NULL);
#endif
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
			if (httpWriteRequest(ssl) < 0) {
				goto L_CLOSE_ERR;
			}
#endif
			goto WRITE_MORE;
		case MATRIXSSL_APP_DATA:
		case MATRIXSSL_APP_DATA_COMPRESSED:
			if (cp.flags != HTTPS_COMPLETE) {
				rc = httpBasicParse(&cp, buf, len, g_trace);
				if (rc < 0) {
					closeConn(ssl, fd);
					if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
					cp.parsebuflen = 0;
					return MATRIXSSL_ERROR;
				}
				if (rc == HTTPS_COMPLETE) {
					cp.flags = HTTPS_COMPLETE;
				}
			}
			cp.bytes_received += len;
			stats->rbytes += len;
			if (g_trace) {
				psTraceBytes("HTTP DATA", buf, len);
			}
			rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len);
			if (rc < 0) {
				goto L_CLOSE_ERR;
			}
			if (g_bytes_requested > 0) {
				if (cp.bytes_received >= g_bytes_requested) {
					/* We've received all that was requested, so close */
					closeConn(ssl, fd);
					if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
					cp.parsebuflen = 0;
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
			if (*buf == SSL_ALERT_LEVEL_FATAL) {
				psTraceIntInfo("Fatal alert: %d, closing connection.\n",
							*(buf + 1));
				goto L_CLOSE_ERR;
			}
			/* Closure alert is normal (and best) way to close */
			if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
				closeConn(ssl, fd);
				if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
				cp.parsebuflen = 0;
				return MATRIXSSL_SUCCESS;
			}
			psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
				/* No more data in buffer. Might as well read for more. */
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		default:
			/* If rc <= 0 we fall here */
			goto L_CLOSE_ERR;
	}

L_CLOSE_ERR:
	if (cp.flags != HTTPS_COMPLETE) {
		_psTrace("FAIL: No HTTP Response\n");
	} else {
/*
		printf("Received %d bytes %d usecs, state %d\n",
			stats->rbytes, (int)stats->hstime, (int)stats->datatime,
			ssl->hsState);
*/
	}
	matrixSslDeleteSession(ssl);
	close(fd);
	if (cp.parsebuf) free(cp.parsebuf); cp.parsebuf = NULL;
	cp.parsebuflen = 0;
	return MATRIXSSL_ERROR;
}

/******************************************************************************/
/*
	Create an HTTP request and encode it to the SSL buffer
 */
static int32 httpWriteRequest(ssl_t *ssl)
{
	unsigned char   *buf;
	int32			available, requested;

	if (g_closeServer) {
		/* A value of 0 to the 'new' connections is the key to sending the
			server a shutdown message */
		requested = strlen((char *)g_matrixShutdownServer) + 1;
		if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0) {
			return PS_MEM_FAIL;
		}
		if (available < requested) {
			return PS_FAILURE;
		}
		memset(buf, 0x0, requested); /* So strlen will work below */
		strncpy((char *)buf, (char *)g_matrixShutdownServer,
			(uint32)strlen((char *)g_matrixShutdownServer));
		if (matrixSslEncodeWritebuf(ssl, (uint32)strlen((char *)buf)) < 0) {
			return PS_MEM_FAIL;
		}
		return MATRIXSSL_REQUEST_SEND;
	}

	requested = strlen((char *)g_httpRequestHdr) + strlen(g_path) + 1;
	if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0) {
		return PS_MEM_FAIL;
	}
	requested = min(requested, available);
	snprintf((char *)buf, requested, (char *)g_httpRequestHdr, g_path);


	if (g_trace) _psTraceStr("SEND: [%s]\n", (char*)buf);
	if (matrixSslEncodeWritebuf(ssl, strlen((char *)buf)) < 0) {
		return PS_MEM_FAIL;
	}
	return MATRIXSSL_REQUEST_SEND;
}

#ifdef ID_RSA
#ifdef USE_HEADER_KEYS
static int32 loadRsaKeys(uint32 key_len, sslKeys_t *keys,
				unsigned char *CAstream, int32 CAstreamLen)
{
	int32 rc;

	if (key_len == 1024) {
		_psTrace("Using 1024 bit RSA private key\n");
		rc = matrixSslLoadRsaKeysMem(keys, RSA1024, sizeof(RSA1024),
			RSA1024KEY, sizeof(RSA1024KEY), CAstream, CAstreamLen);
	} else if (key_len == 2048) {
		_psTrace("Using 2048 bit RSA private key\n");
		rc = matrixSslLoadRsaKeysMem(keys, RSA2048, sizeof(RSA2048),
			RSA2048KEY, sizeof(RSA2048KEY), CAstream, CAstreamLen);
	} else if (key_len == 4096) {
		_psTrace("Using 4096 bit RSA private key\n");
		rc = matrixSslLoadRsaKeysMem(keys, RSA4096, sizeof(RSA4096),
			RSA4096KEY, sizeof(RSA4096KEY), CAstream, CAstreamLen);
	} else {
		rc = -1;
		psAssert((key_len == 1024) || (key_len == 2048) || (key_len == 4096));
	}

	if (rc < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) {
			psFree(CAstream, NULL);
		}
		matrixSslDeleteKeys(keys);
		matrixSslClose();
	}

	return rc;
}
#endif
#endif

static void usage(void)
{
	printf(
		"\nusage: client { options }\n"
		"\n"
		"Options can be one or more of the following:\n"
		"\n"
		"-b <numBytesPerRequest> - Client request size\n"
		"                          Uses URL path of '/bytes?<numBytesPerRequest>'\n"
		"                          Mutually exclusive with '-u' flag\n"
		"-c <cipherList>         - Comma separated list of ciphers numbers\n"
		"                        - Example cipher numbers:\n"
		"                        - '53' TLS_RSA_WITH_AES_256_CBC_SHA\n"
		"                        - '47' TLS_RSA_WITH_AES_128_CBC_SHA\n"
		"                        - '10' SSL_RSA_WITH_3DES_EDE_CBC_SHA\n"
		"                        - '5'  SSL_RSA_WITH_RC4_128_SHA\n"
		"                        - '4'  SSL_RSA_WITH_RC4_128_MD5\n"
		"-d                      - Disable server certicate name/addr chk\n"
		"-h                      - Help, print usage and exit\n"
		"-k <keyLen>             - RSA keyLen\n"
		"                        - Must be one of 1024, 2048 or 4096\n"
		"-n <numNewSessions>     - Num of new (full handshake) sessions\n"
		"                        - Default 1\n"
		"-p <serverPortNum>      - Port number for SSL/TLS server\n"
		"                        - Default 4433 (HTTPS is 443)\n"
		"-r <numResumedSessions> - Num of resumed SSL/TLS sesssions\n"
		"                        - Default 0\n"
		"-s <serverIpAddress>    - IP address of server machine/interface\n"
		"                        - Default 127.0.0.1 (localhost)\n"
		"-u <url path>           - Path portion of the URL, eg. '/index.html'\n"
		"                          Mutually exclusive with '-b' flag\n"
		"-v <tlsVersion>         - SSL/TLS version to use\n"
		"                        - '0' SSL 3.0\n"
		"                        - '1' TLS 1.0\n"
		"                        - '2' TLS 1.1\n"
		"                        - '3' TLS 1.2 (default)\n"
		"\n");
}

/* Returns number of cipher numbers found, or -1 if an error. */
#include <ctype.h>
static int32 parse_cipher_list(char  *cipherListString,
							   uint32 cipher_array[],
							   uint32 size_of_cipher_array)
{
	uint32 numCiphers, cipher;
	char *endPtr;

	/* Convert the cipherListString into an array of cipher numbers. */
	numCiphers = 0;
	while (cipherListString != NULL) {
		cipher = strtol(cipherListString, &endPtr, 10);
		if (endPtr == cipherListString) {
			printf("The remaining cipherList has no cipher numbers - '%s'\n",
				   cipherListString);
			return -1;
		} else if (size_of_cipher_array <= numCiphers) {
			printf("Too many cipher numbers supplied.  limit is %d\n",
				   size_of_cipher_array);
			return -1;
		}
		cipher_array[numCiphers++] = cipher;
		while (*endPtr != '\0' && !isdigit(*endPtr)) {
			endPtr++;
		}
		cipherListString = endPtr;
		if (*endPtr == '\0') {
			break;
		}
	}

	return numCiphers;
}

/* Return 0 on good set of cmd options, return -1 if a bad cmd option is
   encountered OR a request for help is seen (i.e. '-h' option). */
static int32 process_cmd_options(int32 argc, char **argv)
{
	int   optionChar, key_len, version, numCiphers;
	char *cipherListString;

	// Set some default options:
	memset(g_cipher, 0, sizeof(g_cipher));
	memset(g_ip,     0, sizeof(g_ip));
	memset(g_path,   0, sizeof(g_path));

	strcpy(g_ip,		  "127.0.0.1");
	g_bytes_requested    = 128;
	g_ciphers            = 1;
	g_cipher[0]          = 47;
	g_disableCertNameChk = 0;
	g_key_len            = 1024;
	g_new                = 1;
	g_port               = 4433;
	g_resumed            = 0;
	g_version            = 3;

	opterr = 0;
	while ((optionChar = getopt(argc, argv, "b:c:dhk:n:p:r:s:u:v:")) != -1)
	{
		switch (optionChar)
		{
		case '?':
			return -1;

		case 'b':
			if (*g_path) {
				printf("-b and -u options cannot both be provided\n");
				return -1;
			}
			g_bytes_requested = atoi(optarg);
			snprintf(g_path, sizeof(g_path), "/bytes?%u", g_bytes_requested);
			break;

		case 'c':
			// Convert the cipherListString into an array of cipher numbers.
			cipherListString = optarg;
			numCiphers = parse_cipher_list(cipherListString, g_cipher, 16);
			if (numCiphers <= 0) {
				return -1;
			}
			g_ciphers = numCiphers;
			break;

		case 'd':
			g_disableCertNameChk = 1;
			break;

		case 'h':
			return -1;

		case 'k':
			key_len = atoi(optarg);
			if ((key_len != 1024) && (key_len != 2048) && (key_len != 4096)) {
				printf("-k option must be followed by a key_len whose value "
					   " must be 1024, 2048 or 4096\n");
				return -1;
			}
			g_key_len = key_len;
			break;

		case 'n':
			g_new = atoi(optarg);
			break;

		case 'p':
			g_port = atoi(optarg);
			break;

		case 'r':
			g_resumed = atoi(optarg);
			break;

		case 's':
			strncpy(g_ip, optarg, 15);
			break;

		case 'u':
			if (*g_path) {
				printf("-b and -u options cannot both be provided\n");
				return -1;
			}
			strncpy(g_path, optarg, sizeof(g_path) - 1);
			g_bytes_requested = 0;
			break;

		case 'v':
			version = atoi(optarg);
			if (version < 0 || version > 3) {
				printf("Invalid version: %d\n", version);
				return -1;
			}
			g_version = version;
			break;
		}
	}
	if (*g_path == '\0') {
		strcpy(g_path, "/bytes?1024");
		g_bytes_requested = 1024;
	}

	return 0;
}

/******************************************************************************/
/*
	Main routine. Initialize SSL keys and structures, and make two SSL
	connections, the first with a blank session Id, and the second with
	a session ID populated during the first connection to do a much faster
	session resumption connection the second time.
 */
int32 main(int32 argc, char **argv)
{
	int32			rc, CAstreamLen, i;
	sslKeys_t		*keys;
	sslSessionId_t	*sid;
	struct g_sslstats	stats;
	unsigned char	       *CAstream;
#ifdef USE_CRL
	int32			numLoaded;
#endif
#ifdef WIN32
	WSADATA			wsaData;
	WSAStartup(MAKEWORD(1, 1), &wsaData);
#endif
	if ((rc = matrixSslOpen()) < 0) {
		_psTrace("MatrixSSL library init failure.  Exiting\n");
		return rc;
	}


	if (matrixSslNewKeys(&keys, NULL) < 0) {
		_psTrace("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}

	if (0 != process_cmd_options(argc, argv)) {
		usage();
		return 0;
	}

	if (g_new <= 1 && g_resumed <= 1) {
		g_trace = 1;
	} else {
		g_trace = 0;
	}

	printf("client https://%s:%d%s "
		"new:%d resumed:%d keylen:%d nciphers:%d version:%s\n",
		g_ip, g_port, g_path, g_new, g_resumed, g_key_len,
		g_ciphers, g_strver[g_version]);


#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_HEADER_KEYS
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
		CAstream = psMalloc(NULL, CAstreamLen);
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
		return rc;
	}
#endif

#ifdef ID_ECDH_RSA
	if ((rc = matrixSslLoadEcKeysMem(keys, ECDHRSA521, sizeof(ECDHRSA521),
			ECDHRSA521KEY, sizeof(ECDHRSA521KEY), (unsigned char*)CAstream,
			CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef ID_ECDH_ECDSA
	if ((rc = matrixSslLoadEcKeysMem(keys, EC384, sizeof(EC384),
			EC384KEY, sizeof(EC384KEY),	(unsigned char*)CAstream,
			CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

	if (CAstream) psFree(CAstream, NULL);

#else
/*
	File based keys
*/
	CAstreamLen = 0;
#ifdef USE_RSA_CIPHER_SUITE
	CAstreamLen += (int32)strlen(rsaCAFile) + 1;
#ifdef USE_ECC_CIPHER_SUITE
	CAstreamLen += (int32)strlen(ecdhRsaCAFile) + 1;
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
	CAstreamLen += (int32)strlen(ecCAFile) + 1;
#endif
	if (CAstreamLen > 0) {
		CAstream = psMalloc(NULL, CAstreamLen);
		memset(CAstream, 0x0, CAstreamLen);
	} else {
		CAstream = NULL;
	}

	CAstreamLen = 0;
#ifdef USE_RSA_CIPHER_SUITE
	memcpy(CAstream, rsaCAFile,	strlen(rsaCAFile));
	CAstreamLen += strlen(rsaCAFile);
#ifdef USE_ECC_CIPHER_SUITE
	memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
	memcpy(CAstream + CAstreamLen, ecdhRsaCAFile,  strlen(ecdhRsaCAFile));
	CAstreamLen += strlen(ecdhRsaCAFile);
#endif
#endif
#ifdef USE_ECC_CIPHER_SUITE
	if (CAstreamLen > 0) {
		memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
	}
	memcpy(CAstream + CAstreamLen, ecCAFile,  strlen(ecCAFile));
#endif

/* Load Identiy */
#ifdef EXAMPLE_RSA_KEYS
	if ((rc = matrixSslLoadRsaKeys(keys, rsaCertFile, rsaPrivkeyFile, NULL,
			(char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_ECDH_RSA_KEYS
	if ((rc = matrixSslLoadEcKeys(keys, ecdhRsaCertFile, ecdhRsaPrivkeyFile,
			NULL, (char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_EC_KEYS
	if ((rc = matrixSslLoadEcKeys(keys, ecCertFile, ecPrivkeyFile, NULL,
			(char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		if (CAstream) psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

	if (CAstream) psFree(CAstream, NULL);
#endif /* USE_HEADER_KEYS */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	for (rc = 0; rc < 8; rc++) {
		matrixSslLoadPsk(keys, pskTable[rc].key, sizeof(pskTable[rc].key),
			pskTable[rc].id, sizeof(pskTable[rc].id));
	}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_CRL
	if (matrixSslGetCRL(keys, crlCb, &numLoaded) < 0) {
		_psTrace("WARNING: A CRL failed to load\n");
	}
	_psTraceInt("CRLs loaded: %d\n", numLoaded);
#endif

	memset(&stats, 0x0, sizeof(struct g_sslstats));
	printf("=== %d new connections ===\n", g_new);

	if (g_new == 0) {
		/* Special case where client is being used to remotely shut down
			the server for automated tests */
		g_closeServer = 1;
		g_bytes_requested = 0; /* Disable data exchange in this case */
		g_new++;
	}

	for (i = 0; i < g_new; i++) {
		matrixSslNewSessionId(&sid, NULL);
		rc = httpsClientConnection(keys, sid, &stats);
		if (rc < 0) {
			printf("F %d/%d\n", i, g_new);
			return 0;
		} else {
			printf("N"); fflush(stdout);
		}
		/* Leave the final sessionID for resumed connections */
		if (i + 1 < g_new) matrixSslDeleteSessionId(sid);
	}
	if (g_new) printf("\n");
	if (g_bytes_requested > 0) {
		psAssert(g_bytes_requested * g_new == stats.rbytes);
	}
	printf("%d bytes received\n", stats.rbytes);
#ifdef USE_HIGHRES_TIME
	printf("%d usec (%d avg usec/conn SSL handshake overhead)\n",
		(int)stats.hstime, (int)(stats.hstime/ g_new));
	printf("%d usec (%d avg usec/conn SSL data overhead)\n",
		(int)stats.datatime, (int)(stats.datatime/ g_new));
#else
	printf("%d msec (%d avg msec/conn SSL handshake overhead)\n",
		(int)stats.hstime, (int)(stats.hstime/ g_new));
	printf("%d msec (%d avg msec/conn SSL data overhead)\n",
		(int)stats.datatime, (int)(stats.datatime/ g_new));
#endif

	memset(&stats, 0x0, sizeof(struct g_sslstats));
	printf("=== %d resumed connections ===\n", g_resumed);
	for (i = 0; i < g_resumed; i++) {
		rc = httpsClientConnection(keys, sid, &stats);
		if (rc < 0) {
			printf("f %d/%d\n", i, g_resumed);
		} else {
			printf("R"); fflush(stdout);
		}
	}
	if (g_resumed) {
		if (g_bytes_requested > 0) {
			psAssert(g_bytes_requested * g_resumed == stats.rbytes);
		}
		printf("\n%d bytes received\n", stats.rbytes);
#ifdef USE_HIGHRES_TIME
		printf("%d usec (%d avg usec/conn SSL handshake overhead)\n",
			(int)stats.hstime, (int)(stats.hstime/ g_resumed));
		printf("%d usec (%d avg usec/conn SSL data overhead)\n",
			(int)stats.datatime, (int)(stats.datatime/ g_resumed));
#else
		printf("%d msec (%d avg msec/conn SSL handshake overhead)\n",
			(int)stats.hstime, (int)(stats.hstime/ g_resumed));
		printf("%d msec (%d avg msec/conn SSL data overhead)\n",
			(int)stats.datatime, (int)(stats.datatime/ g_resumed));
#endif
	}

	matrixSslDeleteSessionId(sid);

	matrixSslDeleteKeys(keys);
	matrixSslClose();

#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif
	return 0;
}

/******************************************************************************/
/*
	Close a socket and free associated SSL context and buffers
	An attempt is made to send a closure alert
 */
static void closeConn(ssl_t *ssl, SOCKET fd)
{
	unsigned char	*buf;
	int32			len;
#if 1
	/* Set the socket to non-blocking to flush remaining data */
#ifdef POSIX
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
#ifdef WIN32
	len = 1;		/* 1 for non-block, 0 for block */
	ioctlsocket(fd, FIONBIO, &len);
#endif
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
#endif
	matrixSslDeleteSession(ssl);
	if (fd != INVALID_SOCKET) {
		close(fd);
	}
}

static int32 extensionCb(ssl_t *ssl, unsigned short extType,
							unsigned short extLen, void *e)
{
	unsigned char	*c;
	short			len;
	char			proto[128];

	c = (unsigned char*)e;

	if (extType == EXT_ALPN) {
		memset(proto, 0x0, 128);
		/* two byte proto list len, one byte proto len, then proto */
		c += 2; /* Skip proto list len */
		len = *c; c++;
		memcpy(proto, c, len);
		printf("Server agreed to use %s\n", proto);
	}
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Example callback to show possiblie outcomes of certificate validation.
	If this callback is not registered in matrixSslNewClientSession
	the connection will be accepted or closed based on the alert value.
 */
static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psX509Cert_t	*next;

	/* Did we even find a CA that issued the certificate? */
	if (alert == SSL_ALERT_UNKNOWN_CA) {
			/* Example to allow anonymous connections based on a define */
		if (ALLOW_ANON_CONNECTIONS) {
			if (g_trace) {
				_psTraceStr("Allowing anonymous connection for: %s.\n",
						cert->subject.commonName);
			}
			return SSL_ALLOW_ANON_CONNECTION;
		}
		_psTrace("ERROR: No matching CA found.  Terminating connection\n");
	}

	/*
 		If the expectedName passed to matrixSslNewClientSession does not
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
		_psTraceStr("ERROR: %s not found in cert subject names\n",
			ssl->expectedName);
	}

	if (alert == SSL_ALERT_CERTIFICATE_EXPIRED) {
#ifdef POSIX
		_psTrace("ERROR: A cert did not fall within the notBefore/notAfter window\n");
#else
		_psTrace("WARNING: Certificate date window validation not implemented\n");
		alert = 0;
#endif
	}

	if (alert == SSL_ALERT_ILLEGAL_PARAMETER) {
		_psTrace("ERROR: Found correct CA but X.509 extension details are wrong\n");
	}

	/* Key usage related problems on chain */
	for (next = cert; next != NULL; next = next->next) {
		if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION) {
			if (next->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
				_psTrace("CA keyUsage extension doesn't allow cert signing\n");
			}
			if (next->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
				_psTrace("Cert extendedKeyUsage extension doesn't allow TLS\n");
			}
		}
	}

	if (alert == SSL_ALERT_BAD_CERTIFICATE) {
		/* Should never let a connection happen if this is set.  There was
			either a problem in the presented chain or in the final CA test */
		_psTrace("ERROR: Problem in certificate validation.  Exiting.\n");
	}


	if (g_trace && alert == 0) _psTraceStr("SUCCESS: Validated cert for: %s.\n",
		cert->subject.commonName);

#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return alert;
}

#ifdef USE_CRL
/* Basic example of matrixSslGetCRL callback for downloading a CRL from a given
	URL	and	passing	the CRL contents to matrixSslLoadCRL

	< 0 - Error loading CRL
	> 0 - Success
*/
static unsigned char crl_getHdr[] = "GET ";
#define GET_OH_LEN		4
static unsigned char crl_httpHdr[] = " HTTP/1.0\r\n";
#define HTTP_OH_LEN		11
static unsigned char crl_hostHdr[] = "Host: ";
#define HOST_OH_LEN		6
static unsigned char crl_acceptHdr[] = "\r\nAccept: */*\r\n\r\n";
#define ACCEPT_OH_LEN	17

#define HOST_ADDR_LEN	64	/* max to hold 'www.something.com' */
#define GET_REQ_LEN		128	/* max to hold http GET request */
#define CRL_BUF_SIZE	4096	/* max size of incoming CRL */

int32 crlCb(psPool_t *pool, psX509Cert_t *CA, int append, char *url,
				uint32 urlLen)
{
	SOCKET			fd;
	struct hostent	*ip;
	struct in_addr	intaddr;
	char			*pageStart, *replyPtr, *ipAddr;
	char			hostAddr[HOST_ADDR_LEN], getReq[GET_REQ_LEN];
	char			crlBuf[CRL_BUF_SIZE];
	int				hostAddrLen, getReqLen, pageLen;
	int32			transferred;
	int32			err, httpUriLen, port, offset;
	uint32			crlBinLen;

	/* Is URI in expected URL form? */
	if (strstr(url, "http://") == NULL) {
		if (strstr(url, "https://") == NULL) {
			_psTraceStr("crlCb: Unsupported CRL URI: %s\n", url);
			return -1;
		}
		httpUriLen = 8;
		port = 80; /* No example yet of using SSL to fetch CRL */
	} else {
		httpUriLen = 7;
		port = 80;
	}

	/* Parsing host and page and setting up IP address and GET request */
	if ((pageStart = strchr(url + httpUriLen, '/')) == NULL) {
		_psTrace("crlCb: No host/page divider found\n");
		return -1;
	}
	if ((hostAddrLen = (int)(pageStart - url) - httpUriLen) > HOST_ADDR_LEN) {
		_psTrace("crlCb: HOST_ADDR_LEN needs to be increased\n");
		return -1; /* ipAddr too small to hold */
	}

	memset(hostAddr, 0, HOST_ADDR_LEN);
	memcpy(hostAddr, url + httpUriLen, hostAddrLen);
	if ((ip = gethostbyname(hostAddr)) == NULL) {
		_psTrace("crlCb: gethostbyname failed\n");
		return -1;
	}

	memcpy((char *) &intaddr, (char *) ip->h_addr_list[0],
		(size_t) ip->h_length);
	if ((ipAddr = inet_ntoa(intaddr)) == NULL) {
		_psTrace("crlCb: inet_ntoa failed\n");
		return -1;
	}

	pageLen = (urlLen - hostAddrLen - httpUriLen);
	getReqLen = pageLen + hostAddrLen + GET_OH_LEN + HTTP_OH_LEN +
		HOST_OH_LEN + ACCEPT_OH_LEN;
	if (getReqLen > GET_REQ_LEN) {
		_psTrace("crlCb: GET_REQ_LEN needs to be increased\n");
		return -1;
	}

	// Build the request:
	//
	//	GET /page.crl HTTP/1.0
	//	Host: www.host.com
	//	Accept: */*
	//
	memset(getReq, 0, GET_REQ_LEN);
	memcpy(getReq, crl_getHdr, GET_OH_LEN);
	offset = GET_OH_LEN;
	memcpy(getReq + offset, pageStart, pageLen);
	offset += pageLen;
	memcpy(getReq + offset, crl_httpHdr, HTTP_OH_LEN);
	offset += HTTP_OH_LEN;
	memcpy(getReq + offset, crl_hostHdr, HOST_OH_LEN);
	offset += HOST_OH_LEN;
	memcpy(getReq + offset, hostAddr, hostAddrLen);
	offset += hostAddrLen;
	memcpy(getReq + offset, crl_acceptHdr, ACCEPT_OH_LEN);

	/* Connect and send */
	fd = socketConnect(ipAddr, port, &err);
	if (fd == INVALID_SOCKET || err != PS_SUCCESS) {
		_psTraceInt("crlCb: socketConnect failed: %d\n", err);
		return PS_PLATFORM_FAIL;
	}

	/* Send request and receive response */
	offset = 0;
	while (getReqLen) {
		if ((transferred = send(fd, getReq + offset, getReqLen, 0)) < 0) {
			_psTraceInt("crlCb: socket send failed: %d\n", errno);
			close(fd);
			return PS_PLATFORM_FAIL;
		}
		getReqLen -= transferred;
		offset += transferred;
	}

	/* Not a good full recv */
	if ((transferred = recv(fd, crlBuf, CRL_BUF_SIZE, 0)) <= 0) {
		_psTrace("crlCb: socket recv closed or failed\n");
		close(fd);
		return PS_PLATFORM_FAIL;
	}
	if (transferred == CRL_BUF_SIZE) {
		/* CRL larger than max */
		_psTrace("crlCb: CRL_BUF_SIZE needs to be increased\n");
		close(fd);
		return -1;
	}
	close(fd);

	/* Did we get an OK response? */
	if (strstr(crlBuf, "200 OK") == NULL) {
		_psTrace("crlCb: server reply was not '200 OK'\n");
		return -1;
	}
	/* Length parse */
	if ((replyPtr = strstr(crlBuf, "Content-Length: ")) == NULL) {
		return -1;
	}
	crlBinLen = (int)atoi(replyPtr + 16);

	/* Data begins after CRLF CRLF */
	if ((replyPtr = strstr(crlBuf, "\r\n\r\n")) == NULL) {
		return -1;
	}
	/* A sanity test that the length matches the remainder */
	if ((transferred - (replyPtr - crlBuf) - 4) != crlBinLen) {
		return -1;
	}

	/* Lastly, pass the CRL to matrixSslLoadCRL to parse, perform signature
		validation, and cache the revoked certificates for this CA */
	return matrixSslLoadCRL(pool, CA, append, replyPtr + 4, crlBinLen, NULL);
}
#endif

/******************************************************************************/
/*
	Open an outgoing blocking socket connection to a remote ip and port.
	Caller should always check *err value, even if a valid socket is returned
 */
static SOCKET socketConnect(char *ip, int32 port, int32 *err)
{
	struct sockaddr_in	addr;
	SOCKET				fd;
	int32				rc;

	/* By default, this will produce a blocking socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		perror("socket()");
		_psTrace("Error creating socket\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}
#ifdef POSIX
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#if 0
	{
	struct linger		lin;
	rc = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&rc, sizeof(rc));
	rc = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&rc, sizeof(rc));
	lin.l_onoff = 0;
	lin.l_linger = 0;	// Seconds
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&lin, sizeof(struct linger));
	}
	{
	uint32				len;
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rc, &len);
	printf("SO_RCVBUF: %d\n", rc);
	}
#endif
#ifdef POSIX
	rc = 1;
//	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(rc));
//	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#elif defined(WIN32)
	rc = 1;     /* 1 for non-block, 0 for block */
//	ioctlsocket(fd, FIONBIO, &rc);
#endif
#ifdef __APPLE__  /* MAC OS X */
	rc = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&rc, sizeof(rc));
#endif

	memset((char *) &addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((short)port);
	addr.sin_addr.s_addr = inet_addr(ip);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		perror("connect()");
		*err = SOCKET_ERRNO;
	} else {
		*err = 0;
	}
	return fd;
}

#else

/******************************************************************************/
/*
	Stub main for compiling without client enabled
*/
int32 main(int32 argc, char **argv)
{
	printf("USE_CLIENT_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
			" time to run this application\n");
	return -1;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/

