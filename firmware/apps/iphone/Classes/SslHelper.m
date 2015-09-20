// This class contains the MatrixSSL wrapper layer, similar to the other
// MatrixSSL command line sample client application.

#import "SslHelper.h"

#include <netdb.h>

#include "matrixssl/matrixsslApi.h"
#include "sampleCerts/CAcertSrv.h"


static unsigned char g_httpRequestHdr[] = "GET / HTTP/1.0\r\n"
                                          "User-Agent: MatrixSSL/3.x\r\n"
                                          "Accept: */*\r\n"
                                          "Content-Length: 0\r\n"
                                          "\r\n";


// SslHelper (Private) interface ----------------------------------------------
@interface SslHelper (Private)

- (int32) httpProcessResponseData:(unsigned char*)buf
                       withLength:(uint32)length;
- (int32) httpsClientConnectionWithKeys:(sslKeys_t*)keys
                              sessionId:(sslSessionId_t*)sid;

@end


// SslHelper implementation ---------------------------------------------------

@implementation SslHelper

@synthesize ipAddress;
@synthesize port;
@synthesize delegate;


- (void) dealloc
{
    self.ipAddress = nil;

    [super dealloc];
}


- (id) initWithIP:(NSString*)serverIpAddress port:(int32)serverPort
{
    if (self = [super init]) {
        self.ipAddress = serverIpAddress;
        port = serverPort;
    }
    
    return self;
}


// Converts host 'name' into a network presentation address in 'ip_addr'.
void getIPAddressForHostName(const char *name, char *ip, size_t ipLength)
{
    struct hostent *host = gethostbyname(name);
    
    if (host->h_addrtype != AF_INET || host->h_addr_list[0] == NULL) {
        return;
    }
    
    struct in_addr address;
    address.s_addr = *(unsigned long *) host->h_addr_list[0];
    
    inet_ntop(AF_INET, &address, ip, ipLength);
}


// Close a socket and free associated SSL context and buffers.
// An attempt is made to send a closure alert.

static void closeConn(ssl_t *ssl, SOCKET fd)
{
	unsigned char	*buf;
	int32			len;
	
	// Set the socket to non-blocking to flush remaining data
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    
	// Quick attempt to send a closure alert, don't worry about failure
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
	matrixSslDeleteSession(ssl);
	if (fd != INVALID_SOCKET) close(fd);
}


// Open an outgoing blocking socket connection to a remote ip and port.
// Caller should always check *err value, even if a valid socket is returned.

static SOCKET socketConnect(char *ip, int32 port, int32 *err)
{
	struct sockaddr_in	addr;
	SOCKET				fd;
	int32				rc;
	
	/* By default, this will produce a blocking socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		_psTrace("Error creating socket\n");
		*err = SOCKET_ERRNO;
		return INVALID_SOCKET;
	}
	
	memset((char *) &addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((short)port);
	addr.sin_addr.s_addr = inet_addr(ip);
	rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		*err = SOCKET_ERRNO;
	} else {
		*err = 0;
	}
	return fd;
}

// Process an HTTP response from the server.
// Very simple - we just print it, and return success.
// No HTTP validation at all is done on the data.

- (int32) httpProcessResponseData:(unsigned char*)buf withLength:(uint32)length
{
	char	s[2];
	
	s[0] = buf[length - 1]; s[1] = '\0';
	buf[length - 1] = '\0';	// Hack a null terminator on the buffer
    NSString* message = [NSString stringWithFormat:@"%s", buf];
    message = [message stringByAppendingFormat:@"%s", s];
    [delegate handleData:message];

	return PS_SUCCESS;
}


// Create an HTTP request and encode it to the SSL buffer.

static int32 httpWriteRequest(ssl_t *cp)
{
	unsigned char	*buf;
	uint32			available;
	
	if ((available = matrixSslGetWritebuf(cp, &buf, 
                           strlen((char *)g_httpRequestHdr) + 1)) < 0) {
		return PS_MEM_FAIL;
	}
	strncpy((char *)buf, (char *)g_httpRequestHdr, available);
	_psTraceStr("SEND: [%s]\n", (char*)buf);
	if (matrixSslEncodeWritebuf(cp, strlen((char *)buf)) < 0) {
		return PS_MEM_FAIL;
	}
	return MATRIXSSL_REQUEST_SEND;
}


// Example callback to do additional certificate validation.
// If this callback is not registered in matrixSslNewService,
// the connection will be accepted or closed based on the status flag.

static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
	struct tm	t;
	time_t		rawtime;
	char		*c;
	int			y, m, d;
	
	// Example to allow anonymous connections based on a define
	if (alert > 0) {
		_psTraceStr("Allowing anonymous connection for: %s.\n", 
					cert->subject.commonName);
		return SSL_ALLOW_ANON_CONNECTION;
	}
	
	// Validate the dates in the cert
	time(&rawtime);
	localtime_r(&rawtime, &t);
	// Localtime does months from 0-11 and (year-1900)! Normalize it.
	t.tm_mon++;
	t.tm_year += 1900;
	
	// Validate the 'not before' date
	if ((c = cert->notBefore) != NULL) {
		if (strlen(c) < 8) {
			return PS_FAILURE;
		}
		// UTCTIME, defined in 1982, has just a 2 digit year
		if (cert->timeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year < y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon < m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday < d) return PS_FAILURE;
		}
        // _psTraceStr("Validated notBefore: %s\n", cert->notBefore);
	}
	
	// Validate the 'not after' date
	if ((c = cert->notAfter) != NULL) {
		if (strlen(c) < 8) {
			return PS_FAILURE;
		}
		// UTCTIME, defined in 1982 has just a 2 digit year
		if (cert->timeType == ASN_UTCTIME) {
			y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		} else {
			y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') + 
			10 * (c[2] - '0') + (c[3] - '0'); c += 4;
		}
		m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
		d = 10 * (c[0] - '0') + (c[1] - '0'); 
		if (t.tm_year > y) return PS_FAILURE; 
		if (t.tm_year == y) {
			if (t.tm_mon > m) return PS_FAILURE;
			if (t.tm_mon == m && t.tm_mday > d) return PS_FAILURE;
		}
        // _psTraceStr("Validated notAfter: %s\n", cert->notAfter);
	}
    
	_psTraceStr("Validated cert for: %s.\n", cert->subject.commonName);
	
	return PS_SUCCESS;
}


// Make a secure HTTP request to a defined IP and port.
// Connection is made in blocking socket mode.
// The connection is considered successful if the SSL/TLS session is
// negotiated successfully, a request is sent, and a HTTP response is received.

- (int32) httpsClientConnectionWithKeys:(sslKeys_t*)keys
                              sessionId:(sslSessionId_t*)sid
{
	int32			rc, transferred, len, complete;
	ssl_t			*ssl;
	unsigned char	*buf;
	sslSessOpts_t	options;
	SOCKET			fd;
	
	complete = 0;
    
	fd = socketConnect((char *)[self.ipAddress UTF8String], self.port, &rc);
	if (fd == INVALID_SOCKET || rc != PS_SUCCESS) {
        [delegate logDebugMessage:
            [NSString stringWithFormat:@"Connect failed: %d. Exiting", rc]];
		return PS_PLATFORM_FAIL;
	}
	memset(&options, 0x0, sizeof(sslSessOpts_t));
	
	rc = matrixSslNewClientSession(&ssl, keys, sid, 0, 0, certCb, NULL,
		NULL, NULL, &options);
	if (rc != MATRIXSSL_REQUEST_SEND) {
        [delegate logDebugMessage:[NSString stringWithFormat:
                                   @"New Client Session Failed: %d. Exiting",
                                   rc]];
		close(fd);
		return PS_ARG_FAIL;
	}
WRITE_MORE:
	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		transferred = send(fd, buf, len, 0);
		if (transferred <= 0) {
			goto L_CLOSE_ERR;
		} else {
			// Indicate that we've written > 0 bytes of data
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				goto L_CLOSE_ERR;
			}
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				closeConn(ssl, fd);
				return MATRIXSSL_SUCCESS;
			} 
			if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
				// If we sent the Finished SSL message, initiate the HTTP req
				// (This occurs on a resumption handshake)
				if (httpWriteRequest(ssl) < 0) {
					goto L_CLOSE_ERR;
				}
				goto WRITE_MORE;
			}
			// SSL_REQUEST_SEND is handled by loop logic
		}
	}
READ_MORE:
	if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
		goto L_CLOSE_ERR;
	}
	if ((transferred = recv(fd, buf, len, 0)) < 0) {
		goto L_CLOSE_ERR;
	}
	// If EOF, remote socket closed. But we haven't received the HTTP response 
    // so we consider it an error in the case of an HTTP client
	if (transferred == 0) {
		goto L_CLOSE_ERR;
	}
	if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &buf, 
									(uint32*)&len)) < 0) {
		goto L_CLOSE_ERR;
	}

PROCESS_MORE:
	switch (rc) {
		case MATRIXSSL_HANDSHAKE_COMPLETE:
			// We got the Finished SSL message, initiate the HTTP req
			if (httpWriteRequest(ssl) < 0) {
				goto L_CLOSE_ERR;
			}
			goto WRITE_MORE;
		case MATRIXSSL_APP_DATA:
            [delegate logDebugMessage:@"SUCCESS: Received HTTP Response:\n"];
			[self httpProcessResponseData:buf withLength:len];
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
				// We assume response is complete, close the connection
				closeConn(ssl, fd);
				return MATRIXSSL_SUCCESS;
			}
			goto PROCESS_MORE;
		case MATRIXSSL_REQUEST_SEND:
			goto WRITE_MORE;
		case MATRIXSSL_REQUEST_RECV:
			goto READ_MORE;
		case MATRIXSSL_RECEIVED_ALERT:
			// The first byte of the buffer is the level
			// The second byte is the description
			if (*buf == SSL_ALERT_LEVEL_FATAL) {
                [delegate logDebugMessage:
                    [NSString stringWithFormat:
                         @"Fatal alert: %d, closing connection.", *(buf + 1)]];
				goto L_CLOSE_ERR;
			}
			psTraceIntInfo("Warning alert: %d\n", *(buf + 1));
            [delegate logDebugMessage:
                [NSString stringWithFormat:@"Warning alert: %d\n", *(buf + 1)]];
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
                /* No more data in buffer. Might as well read for more. */
                goto READ_MORE;
            }
            goto PROCESS_MORE;
		default:
			goto L_CLOSE_ERR;
	}
	
L_CLOSE_ERR:
    [delegate logDebugMessage:@"FAIL: No HTTP Response"];
	matrixSslDeleteSession(ssl);
	close(fd);
	return MATRIXSSL_ERROR;
}


- (void) connect
{
    int32 err = matrixSslOpen();
    if (err) {
        return;
    }
    
    sslKeys_t* keys;
    if (matrixSslNewKeys(&keys) < 0) {
        return;
    }
    
    err = matrixSslLoadRsaKeysMem(keys, NULL, 0, NULL, 0, 
                                  CAcertSrvBuf, sizeof(CAcertSrvBuf));
    if (err < 0) {
        matrixSslDeleteKeys(keys);
        matrixSslClose();
        return;
    }
    
    sslSessionId_t *sid;
    matrixSslNewSessionId(&sid);
    
    [self httpsClientConnectionWithKeys:keys sessionId:sid];
   
	matrixSslDeleteSessionId(sid); 
    matrixSslDeleteKeys(keys);
    matrixSslClose();
}



@end
