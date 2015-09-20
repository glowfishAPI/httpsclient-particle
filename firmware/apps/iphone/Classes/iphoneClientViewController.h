/**
 *	@file    iphoneClientViewController.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Summary.
 */
// The class that controls the user interface.

#import <UIKit/UIKit.h>

#import "SslDelegateProtocol.h"


@interface IphoneClientViewController : UIViewController
										<SslDelegateProtocol,
										 UITextFieldDelegate>
{
	// Host name or IP address string from the user.
	UITextField* urlField;

	// Port number from the user.
	UITextField* portField;

	// User interface elements for controlling actions.
	UIButton* connectButton;
	UIButton* clearButton;

	// For displaying debug and data messages for the SSL connection.
	UITextView* textView;
}

@property (nonatomic, retain) IBOutlet UITextField* urlField;
@property (nonatomic, retain) IBOutlet UITextField* portField;
@property (nonatomic, retain) IBOutlet UIButton* connectButton;
@property (nonatomic, retain) IBOutlet UITextView* textView;
@property (nonatomic, retain) IBOutlet UIButton* clearButton;

// User interface action callbacks.
- (IBAction) connect:(id)sender;
- (IBAction) clear:(id)sender;

@end

