/**
 *	@file    server.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Non-blocking MatrixSSL server example supporting multiple connections.
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

#include "app.h"
#include "matrixssl/matrixsslApi.h"

#ifdef USE_SERVER_SIDE_SSL

#include <signal.h>         /* Defines SIGTERM, etc. */

#ifdef WIN32
#pragma message("DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.")
#else
#warning "DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS."
#endif

/*	Pick ONE cipher suite type you want to use to auto select a certificate
	and private key identity that support those algorithms.

	In general, it works the other way: a server would obtain an identity
	certificate and private key	and then only enable cipher suites that the
	material supports.
*/
#define ID_RSA /* Standard RSA suites.  RSA Key Exchange and Authentication */
//#define ID_DHE_RSA /* Diffie-Hellman key exchange.  RSA Authentication */
//#define ID_DH_ANON /* Diffie-Hellman key exchange.  No auth */
//#define ID_DHE_PSK /* Diffie-Hellman key exchange.  Pre-Shared Key Auth */
//#define ID_PSK /* Basic Pre-Shared Key suites */
//#define ID_ECDH_ECDSA /* Elliptic Curve Key Exchange and Authentication */
//#define ID_ECDHE_ECDSA /* Same as above with ephemeral Key Exchange */
//#define ID_ECDHE_RSA /* Ephemeral EC Key Exchange, RSA Authentication */
//#define ID_ECDH_RSA /* EC Key Exchange, RSA Authentication */

#define ALLOW_ANON_CONNECTIONS	1
#define USE_HEADER_KEYS

/*	The keys that are loaded are compatible with the MatrixSSL sample client.
	The CA files loaded assume the same authentication mechanism as the
	cipher suite
*/
#ifdef USE_HEADER_KEYS
/* Identity Key and Cert */
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
#include "sampleCerts/RSA/1024_RSA.h"
#include "sampleCerts/RSA/1024_RSA_KEY.h"
#endif

#if defined(ID_DHE_RSA) || defined(ID_ECDHE_RSA)
#define EXAMPLE_RSA_KEYS
#include "sampleCerts/RSA/1024_RSA.h"
#include "sampleCerts/RSA/1024_RSA_KEY.h"
#endif

#if defined(ID_ECDHE_ECDSA) || defined(ID_ECDH_ECDSA)
#define EXAMPLE_EC_KEYS
#include "sampleCerts/EC/192_EC.h"
#include "sampleCerts/EC/192_EC_KEY.h"
#include "sampleCerts/EC/256_EC.h"
#include "sampleCerts/EC/256_EC_KEY.h"
#include "sampleCerts/EC/521_EC.h"
#include "sampleCerts/EC/521_EC_KEY.h"
#endif

#ifdef ID_ECDH_RSA
#define EXAMPLE_ECDH_RSA_KEYS
#include "sampleCerts/ECDH_RSA/256_ECDH-RSA.h"
#include "sampleCerts/ECDH_RSA/256_ECDH-RSA_KEY.h"
#endif

#ifdef REQUIRE_DH_PARAMS
#include "sampleCerts/dh1024.h"
#endif

/*	CA files for client auth are selected more generously.  If the algorithm
	type is supported, we'll load it */
#ifdef USE_RSA
#include "sampleCerts/RSA/ALL_RSA_CAS.h"
#ifdef USE_ECC
#include "sampleCerts/ECDH_RSA/ALL_ECDH-RSA_CAS.h"
#endif /* USE_ECC */
#endif /* USE_RSA */
#ifdef USE_ECC
#include "sampleCerts/EC/ALL_EC_CAS.h"
#endif /* USE_ECC */


/* File-based keys */
#else
#ifdef ID_RSA
#define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "../sampleCerts/RSA/1024_RSA.pem";
static char rsaPrivkeyFile[] = "../sampleCerts/RSA/1024_RSA_KEY.pem";

#endif

#if defined(ID_DHE_RSA) || defined(ID_ECDHE_RSA)
#define EXAMPLE_RSA_KEYS
static char rsaCertFile[] = "../sampleCerts/RSA/1024_RSA.pem";
static char rsaPrivkeyFile[] = "../sampleCerts/RSA/1024_RSA_KEY.pem";
#endif

#if defined(ID_ECDHE_ECDSA) || defined(ID_ECDH_ECDSA)
#define EXAMPLE_EC_KEYS
static char ecCertFile[] = "../sampleCerts/EC/521_EC.pem";
static char ecPrivkeyFile[] = "../sampleCerts/EC/521_EC_KEY.pem";
#endif

#ifdef ID_ECDH_RSA
#define EXAMPLE_ECDH-RSA_KEYS
static char ecdhRsaCertFile[] = "../sampleCerts/ECDH_RSA/256_ECDH-RSA.pem";
static char ecdhRsaPrivkeyFile[] = "../sampleCerts/ECDH_RSA/256_ECDH-RSA_KEY.pem";
#endif

#ifdef REQUIRE_DH_PARAMS
static char dhParamFile[] = "../sampleCerts/dh1024.pem";
#endif

/*	CA files for client auth are selected more generously.  If the algorithm
	type is supported, we'll load it */
#ifdef USE_RSA
static char rsaCAFile[] = "../sampleCerts/RSA/ALL_RSA_CAS.pem";
#ifdef USE_ECC
static char ecdhRsaCAFile[] = "../sampleCerts/ECDH_RSA/ALL_ECDH-RSA_CAS.pem";
#endif /* USE_ECC */
#endif /* USE_RSA */
#ifdef USE_ECC
static char ecCAFile[] = "../sampleCerts/EC/ALL_EC_CAS.pem";
#endif /* USE_ECC */

#endif /* USE_FILE_KEYS */

#ifdef USE_PSK_CIPHER_SUITE
#include "sampleCerts/psk.h"
#endif /* PSK */

#ifdef USE_STATELESS_SESSION_TICKETS
static int32 sessTicketCb(void *keys, unsigned char name[16], short found);

static unsigned char sessTicketSymKey[32] = {
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08};

static unsigned char sessTicketMacKey[32] = {
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08,
	0x2A, 0x34, 0xC2, 0x11, 0x45, 0x8F, 0x3D, 0x08};
#endif


/* #define USE_SERVER_NAME_INDICATION */

/********************************** Defines ***********************************/

#define SSL_TIMEOUT			45000
#define SELECT_TIME			1000
#define RESPONSE_REC_LEN	1024 * 16

#define	GOTO_SANITY			32	/* Must be <= 255 */
/*
	The ACCEPT_QUEUE is an optimization mechanism that allows the server to
	accept() up to this many connections before serving any of them.  The
	reason is that the timeout waiting for the accept() is much shorter
	than the timeout for the actual processing.
*/
#define	ACCEPT_QUEUE		16

/********************************** Globals ***********************************/

static DLListEntry		g_conns;
static int32			g_exitFlag;
static int				g_proto;
static unsigned char	g_httpResponseHdr[] = "HTTP/1.0 200 OK\r\n"
	"Server: MatrixSSL/" MATRIXSSL_VERSION "\r\n"
	"Pragma: no-cache\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-type: text/plain\r\n"
	"Content-length: 9\r\n"
	"\r\n"
	"MatrixSSL";


/****************************** Local Functions *******************************/

static int32 selectLoop(sslKeys_t *keys, SOCKET lfd);
static int32 httpWriteResponse(httpConn_t *conn);
static void setSocketOptions(SOCKET fd);
static SOCKET socketListen(short port, int32 *err);
static void closeConn(httpConn_t *cp, int32 reason);

#ifdef POSIX
static void sigsegv_handler(int i);
static void sigintterm_handler(int i);
static int32 sighandlers(void);
#endif /* POSIX */


#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE
/******************************************************************************/
/*
	Example callback to show possiblie outcomes of certificate validation.
	If this callback is not registered in matrixSslNewServerSession
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
			_psTraceStr("Allowing anonymous connection for: %s.\n",
				cert->subject.commonName);
			return SSL_ALLOW_ANON_CONNECTION;
		}
		_psTrace("ERROR: No matching CA found.  Terminating connection\n");
	}

	/* Test if the server certificate didn't match the name passed to
		expectedName in matrixSslNewClientSession */
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

	/* Key usage related problems */
	next = cert;
	while (next) {
		if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION) {
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
				_psTrace("CA keyUsage extension doesn't allow cert signing\n");
			}
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
				_psTrace("Cert extendedKeyUsage extension doesn't allow TLS\n");
			}
		}
		next = next->next;
	}

	if (alert == SSL_ALERT_BAD_CERTIFICATE) {
		/* Should never let a connection happen if this is set.  There was
			either a problem in the presented chain or in the final CA test */
		_psTrace("ERROR: Problem in certificate validation.  Exiting.\n");
	}


	if (alert == 0) _psTraceStr("SUCCESS: Validated cert for: %s.\n",
		cert->subject.commonName);

#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return alert;
}
#else
#define certCb NULL /* Only PSK suites so no certificates are used */
#endif
#else
#define certCb NULL /* No client auth so no possibility of cert cback */
#endif /* USE_CLIENT_AUTH */

#ifdef USE_SERVER_NAME_INDICATION
static 	sslKeys_t	*sni_keys = NULL;
static void SNI_callback(void *ssl, char *hostname, int32 hostnameLen,
				sslKeys_t **newKeys)
{
	ssl_t	*lssl;
	lssl = (ssl_t*)ssl;

#if CHANGE_KEYS_EXAMPLE
	matrixSslNewKeys(&sni_keys);

	if (matrixSslLoadEcKeys(sni_keys, "../sampleCerts/EC/256_EC.pem",
			"../sampleCerts/EC/256_EC_KEY.pem", NULL,
			"../sampleCerts/EC/ALL_EC_CAS.pem")
			 < 0) {
		_psTrace("SNI key load failed.  Exiting\n");
		matrixSslDeleteKeys(sni_keys);
		sni_keys = NULL;
	}
	*newKeys = sni_keys;
#else
	*newKeys = lssl->keys; /* Just use the currently loaded keys */
#endif
	return;
}
#endif /* USE_SNI */

#ifdef USE_ALPN
/*	Callback to process Application Layer Protocol extension sent from client.
	Return value is passed back in "*index":

		Return the INDEX of the proto[] array for the protocol you are agreeing
			to use.  It will be sent as a reply in the SERVER_HELLO extensions.

		Return < 0 if you want to send no_application_protocol alert and stop
			the handshake

		Don't touch index if no reply ALPN extension should be inclued
*/
static void ALPN_callback(void *ssl, short protoCount,
			char *proto[MAX_PROTO_EXT], int32 protoLen[MAX_PROTO_EXT],
			int32 *index)
{
	int32 i;

	for (i = 0; i < protoCount; i++) {
		if (memcmp(proto[i], "http/1.0", 8) == 0) {
			if (protoLen[i] == 8) {
				*index = i;
				return;
			}
		}
	}
	return;
}
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
int32 sessTicketCb(void *keys, unsigned char name[16], short found)
{
	if (found) {
		/* Was already cached */
		return PS_SUCCESS;
	}
	/* Example.  If name was located, the keys would be loaded this way */
	return matrixSslLoadSessionTicketKeys((sslKeys_t*)keys, name,
			sessTicketSymKey, 32, sessTicketMacKey, 32);
}
#endif
/******************************************************************************/
/*
	Non-blocking socket event handler
	Wait one time in select for events on any socket
	This will accept new connections, read and write to sockets that are
	connected, and close sockets as required.
 */
static int32 selectLoop(sslKeys_t *keys, SOCKET lfd)
{
	httpConn_t		*cp;
	psTime_t		now;
	DLListEntry		connsTmp;
	DLListEntry		*pList;

	fd_set			readfd, writefd;
	struct timeval	timeout;
	SOCKET			fd, maxfd;

	unsigned char	*buf;
	int32			rc, len, transferred, val;
	unsigned char	rSanity, wSanity, acceptSanity;

	sslSessOpts_t	options;

	DLListInit(&connsTmp);
	rc = PS_SUCCESS;
	maxfd = INVALID_SOCKET;
	timeout.tv_sec = SELECT_TIME / 1000;
	timeout.tv_usec = (SELECT_TIME % 1000) * 1000;
	FD_ZERO(&readfd);
	FD_ZERO(&writefd);

	/* Always set readfd for listening socket */
	FD_SET(lfd, &readfd);
	if (lfd > maxfd) {
		maxfd = lfd;
	}
/*
	Check timeouts and set readfd and writefd for connections as required.
	We use connsTemp so that removal on error from the active iteration list
		doesn't interfere with list traversal
 */
	psGetTime(&now, NULL);
	while (!DLListIsEmpty(&g_conns)) {
		pList = DLListGetHead(&g_conns);
		cp = DLListGetContainer(pList, httpConn_t, List);
		DLListInsertTail(&connsTmp, &cp->List);
		/*	If timeout != 0 msec ith no new data, close */
		if (cp->timeout && (psDiffMsecs(cp->time, now, NULL) >
				(int32)cp->timeout)) {
			closeConn(cp, PS_TIMEOUT_FAIL);
			continue;	/* Next connection */
		}
		/* Always select for read */
		FD_SET(cp->fd, &readfd);
		/* Select for write if there's pending write data or connection */
		if (matrixSslGetOutdata(cp->ssl, NULL) > 0) {
			FD_SET(cp->fd, &writefd);
		}
		/* Housekeeping for maxsock in select call */
		if (cp->fd > maxfd) {
			maxfd = cp->fd;
		}
	}

	/* Use select to check for events on the sockets */
	if ((val = select(maxfd + 1, &readfd, &writefd, NULL, &timeout)) <= 0) {
		/* On error, restore global connections list */
		while (!DLListIsEmpty(&connsTmp)) {
			pList = DLListGetHead(&connsTmp);
			cp = DLListGetContainer(pList, httpConn_t, List);
			DLListInsertTail(&g_conns, &cp->List);
		}
		/* Select timeout */
		if (val == 0) {
			return PS_TIMEOUT_FAIL;
		}
		/* Woke due to interrupt */
		if (SOCKET_ERRNO == EINTR) {
			return PS_TIMEOUT_FAIL;
		}
		/* Should attempt to handle more errnos, such as EBADF */
		return PS_PLATFORM_FAIL;
	}

	/* Check listener for new incoming socket connections */
	if (FD_ISSET(lfd, &readfd)) {
		for (acceptSanity = 0; acceptSanity < ACCEPT_QUEUE; acceptSanity++) {
			fd = accept(lfd, NULL, NULL);
			if (fd == INVALID_SOCKET) {
				break;	/* Nothing more to accept; next listener */
			}
			setSocketOptions(fd);
			cp = malloc(sizeof(httpConn_t));
			memset(cp, 0x0, sizeof(httpConn_t));

			memset(&options, 0x0, sizeof(sslSessOpts_t));
			options.versionFlag = g_proto;
			options.userPtr = keys; /* Just a test */
			//options.truncHmac = -1;
			//options.maxFragLen = -1;
			//options.ecFlags |= SSL_OPT_SECP521R1;
			//options.ecFlags |= SSL_OPT_SECP224R1;
			//options.ecFlags |= SSL_OPT_SECP384R1;


			if ((rc = matrixSslNewServerSession(&cp->ssl, keys, certCb,
					&options)) < 0) {
				close(fd); fd = INVALID_SOCKET;
				continue;
			}

#ifdef USE_SERVER_NAME_INDICATION
			/* Register extension callbacks to manage client connection opts */
			matrixSslRegisterSNICallback(cp->ssl, SNI_callback);
#endif
#ifdef USE_ALPN
			matrixSslRegisterALPNCallback(cp->ssl, ALPN_callback);
#endif

			cp->fd = fd;
			fd = INVALID_SOCKET;
			cp->timeout = SSL_TIMEOUT;
			psGetTime(&cp->time, NULL);
			cp->parsebuf = NULL;
			cp->parsebuflen = 0;
			DLListInsertTail(&connsTmp, &cp->List);
			/* Fake that there is read data available, no harm if there isn't */
			FD_SET(cp->fd, &readfd);
/*			_psTraceInt("=== New Client %d ===\n", cp->fd); */
		}
	}

	/* Check each connection for read/write activity */
	while (!DLListIsEmpty(&connsTmp)) {
		pList = DLListGetHead(&connsTmp);
		cp = DLListGetContainer(pList, httpConn_t, List);
		DLListInsertTail(&g_conns, &cp->List);

		rSanity = wSanity = 0;
/*
		See if there's pending data to send on this connection
		We could use FD_ISSET, but this is more reliable for the current
			state of data to send.
 */
WRITE_MORE:
		if ((len = matrixSslGetOutdata(cp->ssl, &buf)) > 0) {
			/* Could get a EWOULDBLOCK since we don't check FD_ISSET */
			transferred = send(cp->fd, buf, len, MSG_DONTWAIT);
			if (transferred <= 0) {
#ifdef WIN32
				if (SOCKET_ERRNO != EWOULDBLOCK &&
					SOCKET_ERRNO != WSAEWOULDBLOCK) {

#else
				if (SOCKET_ERRNO != EWOULDBLOCK) {
#endif
					closeConn(cp, PS_PLATFORM_FAIL);
					continue;	/* Next connection */
				}
			} else {
				/* Indicate that we've written > 0 bytes of data */
				if ((rc = matrixSslSentData(cp->ssl, transferred)) < 0) {
					closeConn(cp, PS_ARG_FAIL);
					continue;	/* Next connection */
				}
				if (rc == MATRIXSSL_REQUEST_CLOSE) {
					closeConn(cp, MATRIXSSL_REQUEST_CLOSE);
					continue;	/* Next connection */
				} else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
					/* If the protocol is server initiated, send data here */
#ifdef ENABLE_FALSE_START
					/* OR this could be a Chrome browser using
						FALSE_START and the application data is already
						waiting in our inbuf for processing */
					if ((rc = matrixSslReceivedData(cp->ssl, 0,
								&buf, (uint32*)&len)) < 0) {
							closeConn(cp, 0);
							continue;	/* Next connection */
					}
					if (rc > 0) { /* There was leftover data */
						goto PROCESS_MORE;
					}
#endif /* ENABLE_FALSE_START  */

				}
				/* Update activity time */
				psGetTime(&cp->time, NULL);
				/* Try to send again if more data to send */
				if (rc == MATRIXSSL_REQUEST_SEND || transferred < len) {
					if (wSanity++ < GOTO_SANITY) goto WRITE_MORE;
				}
			}
		} else if (len < 0) {
			closeConn(cp, PS_ARG_FAIL);
			continue;	/* Next connection */
		}

/*
		Check the file descriptor returned from select to see if the connection
		has data to be read
 */
		if (FD_ISSET(cp->fd, &readfd)) {
READ_MORE:
			/* Get the ssl buffer and how much data it can accept */
			/* Note 0 is a return failure, unlike with matrixSslGetOutdata */
			if ((len = matrixSslGetReadbuf(cp->ssl, &buf)) <= 0) {
				closeConn(cp, PS_ARG_FAIL);
				continue;	/* Next connection */
			}
			if ((transferred = recv(cp->fd, buf, len, MSG_DONTWAIT)) < 0) {
				/* We could get EWOULDBLOCK despite the FD_ISSET on goto  */
#ifdef WIN32
				if (SOCKET_ERRNO != EWOULDBLOCK &&
					SOCKET_ERRNO != WSAEWOULDBLOCK) {

#else
				if (SOCKET_ERRNO != EWOULDBLOCK) {
#endif
					closeConn(cp, PS_PLATFORM_FAIL);
				}
				continue;	/* Next connection */
			}

			/* If EOF, remote socket closed. This is semi-normal closure.
			   Officially, we should close on closure alert. */
			if (transferred == 0) {
/*				psTraceIntInfo("Closing connection %d on EOF\n", cp->fd); */
				closeConn(cp, 0);
				continue;	/* Next connection */
			}
/*
			Notify SSL state machine that we've received more data into the
			ssl buffer retreived with matrixSslGetReadbuf.
 */
			if ((rc = matrixSslReceivedData(cp->ssl, (int32)transferred, &buf,
											(uint32*)&len)) < 0) {
				closeConn(cp, 0);
				continue;	/* Next connection */
			}
			/* Update activity time */
			psGetTime(&cp->time, NULL);

PROCESS_MORE:
			/* Process any incoming plaintext application data */
			switch (rc) {
				case MATRIXSSL_HANDSHAKE_COMPLETE:
					/* If the protocol is server initiated, send data here */
					goto READ_MORE;
				case MATRIXSSL_APP_DATA:
				case MATRIXSSL_APP_DATA_COMPRESSED:
					//psTraceBytes("DATA", buf, len);
					/* Remember, must handle if len == 0! */
					if ((rc = httpBasicParse(cp, buf, len, 0)) < 0) {
						_psTrace("Couldn't parse HTTP data.  Closing conn.\n");
						closeConn(cp, PS_PROTOCOL_FAIL);
						continue; /* Next connection */
					}
					if (cp->parsebuf != NULL) {
						/* Test for one of our custom testing messages */
						if (cp->parsebuflen >= 15 &&
								strncmp((const char*)cp->parsebuf,
								"MATRIX_SHUTDOWN", 15) == 0) {
							g_exitFlag = 1;
							matrixSslEncodeClosureAlert(cp->ssl);
							_psTrace("Got MATRIX_SHUTDOWN.  Exiting\n");
							goto WRITE_MORE;
						}
					}
					/* reply to /bytes?<byte count> syntax */
					if (len > 11 &&
							strncmp((char *)buf, "GET /bytes?", 11) == 0) {
						cp->bytes_requested = atoi((char *)buf + 11);
						if (cp->bytes_requested <
								strlen((char *)g_httpResponseHdr) ||
								cp->bytes_requested > 1073741824) {
							cp->bytes_requested =
								strlen((char *)g_httpResponseHdr);
						}
						cp->bytes_sent = 0;
					}
					/* A special test for TLS 1.0 where BEAST workaround used */
					if (len > 10 &&
							strncmp((char *)buf, "ET /bytes?", 10) == 0) {
						cp->bytes_requested = atoi((char *)buf + 10);
						if (cp->bytes_requested <
								strlen((char *)g_httpResponseHdr) ||
								cp->bytes_requested > 1073741824) {
							cp->bytes_requested =
								strlen((char *)g_httpResponseHdr);
						}
						cp->bytes_sent = 0;
					}
					if (rc == HTTPS_COMPLETE) {
						if (httpWriteResponse(cp) < 0) {
							closeConn(cp, PS_PROTOCOL_FAIL);
							continue; /* Next connection */
						}
						/* For HTTP, we assume no pipelined requests, so we
						 close after parsing a single HTTP request */
						/* Ignore return of closure alert, it's optional */
						matrixSslEncodeClosureAlert(cp->ssl);
						rc = matrixSslProcessedData(cp->ssl, &buf, (uint32*)&len);
						if (rc > 0) {
							/* Additional data is available, but we ignore it */
							_psTrace("HTTP data parsing not supported, ignoring.\n");
							closeConn(cp, PS_SUCCESS);
							continue; /* Next connection */
						} else if (rc < 0) {
							closeConn(cp, PS_PROTOCOL_FAIL);
							continue; /* Next connection */
						}
						/* rc == 0, write out our response and closure alert */
						goto WRITE_MORE;
					}
					/* We processed a partial HTTP message */
					if ((rc = matrixSslProcessedData(cp->ssl, &buf, (uint32*)&len)) == 0) {
						goto READ_MORE;
					}
					goto PROCESS_MORE;
				case MATRIXSSL_REQUEST_SEND:
					/* Prevent us from reading again after the write,
					 although that wouldn't be the end of the world */
					FD_CLR(cp->fd, &readfd);
					if (wSanity++ < GOTO_SANITY) goto WRITE_MORE;
					break;
				case MATRIXSSL_REQUEST_RECV:
					if (rSanity++ < GOTO_SANITY) goto READ_MORE;
					break;
				case MATRIXSSL_RECEIVED_ALERT:
					/* The first byte of the buffer is the level */
					/* The second byte is the description */
					if (*buf == SSL_ALERT_LEVEL_FATAL) {
						psTraceIntInfo("Fatal alert: %d, closing connection.\n",
									*(buf + 1));
						closeConn(cp, PS_PROTOCOL_FAIL);
						continue; /* Next connection */
					}
					/* Closure alert is normal (and best) way to close */
					if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
						closeConn(cp, PS_SUCCESS);
						continue; /* Next connection */
					}
					psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
					if ((rc = matrixSslProcessedData(cp->ssl, &buf, (uint32*)&len)) == 0) {
						/* No more data in buffer. Might as well read for more. */
						goto READ_MORE;
					}
					goto PROCESS_MORE;

				default:
					/* If rc <= 0 we fall here */
					closeConn(cp, PS_PROTOCOL_FAIL);
					continue; /* Next connection */
			}
			/* Always try to read more if we processed some data */
			if (rSanity++ < GOTO_SANITY) goto READ_MORE;
		} /*  readfd handling */
	}	/* connection loop */
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Create an HTTP response and encode it to the SSL buffer
 */
#define	TEST_SIZE	16000
static int32 httpWriteResponse(httpConn_t *conn)
{
	unsigned char	*buf;
	ssl_t			*cp;
	int32			available, len, rc;


	cp = conn->ssl;
	if (conn->bytes_requested) {
		/* The /bytes? syntax */
		while (conn->bytes_sent < conn->bytes_requested) {
			len = conn->bytes_requested - conn->bytes_sent;
			if (len > RESPONSE_REC_LEN) {
				len = RESPONSE_REC_LEN;
			}
			psAssert(len > 0);
			rc = matrixSslGetWritebuf(cp, &buf, len);
			if (rc < len) {
				len = rc; /* could have been shortened due to max_frag */
			}
			memset(buf, 'J', len);
			if (conn->bytes_sent == 0) {
				/* Overwrite first N bytes with HTTP header the first time */
				strncpy((char *)buf, (char *)g_httpResponseHdr,
					strlen((char*)g_httpResponseHdr));
			}
			if ((rc = matrixSslEncodeWritebuf(cp, len)) < 0) {
				printf("couldn't encode data %d\n", rc);
			}
			conn->bytes_sent += len;
		}
		return MATRIXSSL_REQUEST_SEND;
	}

	/* Usual reply */

	if ((available = matrixSslGetWritebuf(cp, &buf,
			(uint32)strlen((char *)g_httpResponseHdr) + 1)) < 0) {
		return PS_MEM_FAIL;
	}
	strncpy((char *)buf, (char *)g_httpResponseHdr, available);
	//psTraceBytes("Replying", buf, (uint32)strlen((char *)buf));
	if (matrixSslEncodeWritebuf(cp, (uint32)strlen((char *)buf)) < 0) {
		return PS_MEM_FAIL;
	}
	return MATRIXSSL_REQUEST_SEND;
}

static void usage(void)
{
	printf(	"This application takes no runtime parameters.\n"
			"Configuration is through defines in the source.\n");
}

/******************************************************************************/
/*
	Main non-blocking SSL server
	Initialize MatrixSSL and sockets layer, and loop on select
 */
int32 main(int32 argc, char **argv)
{
	sslKeys_t		*keys;
	SOCKET			lfd;
	unsigned char	*CAstream;
	int32			err, rc, CAstreamLen;
#ifdef USE_STATELESS_SESSION_TICKETS
	unsigned char	randKey[16];
#endif
#ifdef WIN32
	WSADATA			wsaData;
#endif

	if (argc > 1) {
		usage();
		return 0;
	}

#ifdef WIN32
	WSAStartup(MAKEWORD(1, 1), &wsaData);
#endif


	keys = NULL;
	DLListInit(&g_conns);
	g_exitFlag = 0;
	lfd = INVALID_SOCKET;

#ifdef POSIX
	if (sighandlers() < 0) {
		return PS_PLATFORM_FAIL;
	}
#endif	/* POSIX */
	if ((rc = matrixSslOpen()) < 0) {
		_psTrace("MatrixSSL library init failure.  Exiting\n");
		return rc;
	}

	if (matrixSslNewKeys(&keys, NULL) < 0) {
		_psTrace("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}

#ifdef USE_STATELESS_SESSION_TICKETS
	matrixSslSetSessionTicketCallback(keys, sessTicketCb);
	psGetEntropy(randKey, 16, NULL);
	if (matrixSslLoadSessionTicketKeys(keys, randKey,
			sessTicketSymKey, 32, sessTicketMacKey, 32) < 0) {
		_psTrace("Error loading session ticket encryption key\n");
	}
#endif

#ifdef USE_HEADER_KEYS
/*
	In-memory based keys
	Build the CA list first for potential client auth usage
*/
	CAstreamLen = 0;
#ifdef USE_RSA
	CAstreamLen += sizeof(RSACAS);
#ifdef USE_ECC
	CAstreamLen += sizeof(ECDHRSACAS);
#endif
#endif
#ifdef USE_ECC
	CAstreamLen += sizeof(ECCAS);
#endif
	CAstream = psMalloc(NULL, CAstreamLen);

	CAstreamLen = 0;
#ifdef USE_RSA
	memcpy(CAstream, RSACAS, sizeof(RSACAS));
	CAstreamLen += sizeof(RSACAS);
#ifdef USE_ECC
	memcpy(CAstream + CAstreamLen, ECDHRSACAS, sizeof(ECDHRSACAS));
	CAstreamLen += sizeof(ECDHRSACAS);
#endif
#endif
#ifdef USE_ECC
	memcpy(CAstream + CAstreamLen, ECCAS,	sizeof(ECCAS));
	CAstreamLen += sizeof(ECCAS);
#endif

#ifdef EXAMPLE_RSA_KEYS
	if ((rc = matrixSslLoadRsaKeysMem(keys, RSA1024, sizeof(RSA1024),
			RSA1024KEY, sizeof(RSA1024KEY), CAstream, CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_ECDH_RSA_KEYS
	if ((rc = matrixSslLoadEcKeysMem(keys, ECDHRSA256, sizeof(ECDHRSA256),
				   ECDHRSA256KEY, sizeof(ECDHRSA256KEY), CAstream,
				   CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_EC_KEYS
	if ((rc = matrixSslLoadEcKeysMem(keys, EC521, sizeof(EC521),
			EC521KEY, sizeof(EC521KEY), CAstream, CAstreamLen)) < 0) {
//	if ((rc = matrixSslLoadEcKeysMem(keys, EC256, sizeof(EC256),
//			EC256KEY, sizeof(EC256KEY), CAstream, CAstreamLen)) < 0) {
//	if ((rc = matrixSslLoadEcKeysMem(keys, EC192, sizeof(EC192),
//			EC192KEY, sizeof(EC192KEY), CAstream, CAstreamLen)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef REQUIRE_DH_PARAMS
	if (matrixSslLoadDhParamsMem(keys, dhParamBuf1024, sizeof(dhParamBuf1024))
			< 0){
		_psTrace("Unable to load DH parameters\n");
	}
#endif /* DH_PARAMS */

	psFree(CAstream, NULL);
#else /* USE_HEADER_KEYS */
/*
	File based keys
	Build the CA list first for potential client auth usage
*/
	CAstreamLen = 0;
#ifdef USE_RSA
	CAstreamLen += (int32)strlen(rsaCAFile) + 1;
#ifdef USE_ECC
	CAstreamLen += (int32)strlen(ecdhRsaCAFile) + 1;
#endif
#endif
#ifdef USE_ECC
	CAstreamLen += (int32)strlen(ecCAFile) + 1;
#endif
	CAstream = psMalloc(NULL, CAstreamLen);
	memset(CAstream, 0x0, CAstreamLen);

	CAstreamLen = 0;
#ifdef USE_RSA
	memcpy(CAstream, rsaCAFile,	strlen(rsaCAFile));
	CAstreamLen += strlen(rsaCAFile);
#ifdef USE_ECC
	memcpy(CAstream + CAstreamLen, ";", 1); CAstreamLen++;
	memcpy(CAstream + CAstreamLen, ecdhRsaCAFile,  strlen(ecdhRsaCAFile));
	CAstreamLen += strlen(ecdhRsaCAFile);
#endif
#endif
#ifdef USE_ECC
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
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_ECDH_RSA_KEYS
	if ((rc = matrixSslLoadEcKeys(keys, ecdhRsaCertFile, ecdhRsaPrivkeyFile,
			NULL, (char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef EXAMPLE_EC_KEYS
	if ((rc = matrixSslLoadEcKeys(keys, ecCertFile, ecPrivkeyFile, NULL,
			(char*)CAstream)) < 0) {
		_psTrace("No certificate material loaded.  Exiting\n");
		psFree(CAstream, NULL);
		matrixSslDeleteKeys(keys);
		matrixSslClose();
		return rc;
	}
#endif

#ifdef REQUIRE_DH_PARAMS
	if (matrixSslLoadDhParams(keys, dhParamFile) < 0){
		_psTrace("Unable to load DH parameters\n");
	}
#endif

	psFree(CAstream, NULL);
#endif /* USE_HEADER_KEYS */

#ifdef USE_PSK_CIPHER_SUITE
	/* The first one supports the 15-byte openssl PSK ID */
	matrixSslLoadPsk(keys, pskTable[0].key, sizeof(pskTable[0].key),
		pskTable[rc].id, 15);
	for (rc = 0; rc < 8; rc++) {
		matrixSslLoadPsk(keys, pskTable[rc].key, sizeof(pskTable[rc].key),
			pskTable[rc].id, sizeof(pskTable[rc].id));
	}
#endif /* PSK */

	if (argc == 2) {
		switch (atoi(argv[1])) {
		case 0:
			g_proto = SSL_FLAGS_SSLV3;
			break;
		case 1:
			g_proto = SSL_FLAGS_TLS_1_0;
			break;
		case 2:
			g_proto = SSL_FLAGS_TLS_1_1;
			break;
		case 3:
			g_proto = SSL_FLAGS_TLS_1_2;
			break;
		default:
			g_proto = SSL_FLAGS_TLS_1_0;
			break;
		}
	} else {
		g_proto = 0;
	}
	/* Create the listening socket that will accept incoming connections */
	if ((lfd = socketListen(HTTPS_PORT, &err)) == INVALID_SOCKET) {
		_psTraceInt("Can't listen on port %d\n", HTTPS_PORT);
		goto L_EXIT;
	}

	/* Main select loop to handle sockets events */
	while (!g_exitFlag) {
		selectLoop(keys, lfd);
	}

L_EXIT:
	if (lfd != INVALID_SOCKET) close(lfd);
	if (keys) matrixSslDeleteKeys(keys);
	matrixSslClose();

	return 0;
}

/******************************************************************************/
/*
	Close a socket and free associated SSL context and buffers
 */
static void closeConn(httpConn_t *cp, int32 reason)
{
	unsigned char	*buf;
	int32			len;

	DLListRemove(&cp->List);
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(cp->ssl) >= 0) {
		if ((len = matrixSslGetOutdata(cp->ssl, &buf)) > 0) {
			//psTraceBytes("closure alert", buf, len);
			if ((len = send(cp->fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(cp->ssl, len);
			}
		}
	}
	if (cp->parsebuf != NULL) {
		psAssert(cp->parsebuflen > 0);
		free(cp->parsebuf);
		cp->parsebuflen = 0;
	}

	matrixSslDeleteSession(cp->ssl);
#ifdef USE_SERVER_NAME_INDICATION
	if (sni_keys) {
		matrixSslDeleteKeys(sni_keys);
		sni_keys = NULL;
	}
#endif

	if (cp->fd != INVALID_SOCKET) {
		close(cp->fd);
	}
	if (reason >= 0) {
/*		_psTraceInt("=== Closing Client %d ===\n", cp->fd); */
	} else {
		_psTraceInt("=== Closing Client %d on Error ===\n", cp->fd);
	}
	free(cp);
}

/******************************************************************************/
/*
	Establish a listening socket for incomming connections
 */
static SOCKET socketListen(short port, int32 *err)
{
	struct sockaddr_in	addr;
	SOCKET				fd;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		_psTrace("Error creating listen socket\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}

	setSocketOptions(fd);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		_psTrace("Can't bind socket. Port in use or insufficient privilege\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}
	if (listen(fd, SOMAXCONN) < 0) {
		_psTrace("Error listening on socket\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}
	_psTraceInt("Listening on port %d\n", port);
	return fd;
}

/******************************************************************************/
/*
	Make sure the socket is not inherited by exec'd processes
	Set the REUSE flag to minimize the number of sockets in TIME_WAIT
	Then we set REUSEADDR, NODELAY and NONBLOCK on the socket
*/
static void setSocketOptions(SOCKET fd)
{
	int32 rc;

#ifdef POSIX
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	rc = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&rc, sizeof(rc));
#ifdef POSIX
	rc = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(rc));
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#elif defined(WIN32)
	rc = 1;		/* 1 for non-block, 0 for block */
	ioctlsocket(fd, FIONBIO, &rc);
#endif
#ifdef __APPLE__  /* MAC OS X */
	rc = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&rc, sizeof(rc));
#endif
}

#ifdef POSIX
/******************************************************************************/
/*
	Handle some signals on POSIX platforms
	Lets ctrl-c do a clean exit of the server.
 */
static int32 sighandlers(void)
{
	if (signal(SIGINT, sigintterm_handler) == SIG_ERR ||
			signal(SIGTERM, sigintterm_handler) == SIG_ERR ||
			signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
			signal(SIGSEGV, sigsegv_handler) == SIG_ERR) {
		return PS_PLATFORM_FAIL;
	}
	return 0;
}

/* Warn on segmentation violation */
static void sigsegv_handler(int unused)
{
	printf("Segfault! Please report this as a bug to support@peersec.com\n");
	exit(EXIT_FAILURE);
}

/* catch ctrl-c or sigterm */
static void sigintterm_handler(int unused)
{
	g_exitFlag = 1; /* Rudimentary exit flagging */
	printf("Exiting due to interrupt.\n");
}
#endif /* POSIX */


#else

/******************************************************************************/
/*
	Stub main for compiling without server enabled
*/
int32 main(int32 argc, char **argv)
{
	printf("USE_SERVER_SIDE_SSL must be enabled in matrixsslConfig.h at build" \
			" time to run this application\n");
	return -1;
}
#endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/

