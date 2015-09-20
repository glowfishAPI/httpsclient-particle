/**
 *	@file    SslDelegateProtocol.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Summary.
 */
#import <UIKit/UIKit.h>


@protocol SslDelegateProtocol

// The delegate can receive text notifications about status and error messages.
- (void) logDebugMessage:(NSString*)message;

// The delegate can receive data from the SSL connection.
- (void) handleData:(NSString*)data;

@end
