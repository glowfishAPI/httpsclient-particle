/**
 *	@file    SslHelper.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Summary.
 */
// A simple class for wrapping the MatrixSSL calls.

#import <Foundation/Foundation.h>

#include "app.h"

#import "SslDelegateProtocol.h"


@interface SslHelper : NSObject
{
	// Connect to the following IP address and port.
	NSString* ipAddress;
	int32 port;

	// Our delegate object for receiving data and status messages about the
	// SSL connection.
	id<SslDelegateProtocol> delegate;
}


// Initializer method.
- (id) initWithIP:(NSString*)ipAddress port:(int32)port;

// Open an outgoing blocking socket connection to a remote ip and port.
// Caller should always check *err value, even if a valid socket is returned.
- (void) connect;


@property (nonatomic, copy) NSString* ipAddress;
@property int32 port;
@property (nonatomic, assign) id<SslDelegateProtocol> delegate;

@end
