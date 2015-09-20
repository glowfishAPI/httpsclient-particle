#import "iphoneClientViewController.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#import "SslHelper.h"


static const int kDefaultPort = 443;
static const CGFloat kDefaultFontSize = 14.0;


@implementation IphoneClientViewController

@synthesize urlField;
@synthesize portField;
@synthesize connectButton;
@synthesize textView;
@synthesize clearButton;


// SslDelegateProtocol implementation ------------------------------------------

// Adds a message to the text view on the main screen of the application, and
// scrolls to make that message visible.
- (void) logDebugMessage:(NSString*)message;
{
    NSString* newText =
        [[textView text] stringByAppendingFormat:@"%@\n", message];
    [textView setText:newText];
    NSRange range = NSMakeRange(textView.text.length - 1, 1);
    [textView scrollRangeToVisible:range];
    [clearButton setEnabled:YES];
}


// The delegate can receive data from the SSL connection.
- (void) handleData:(NSString*)data
{
    [self logDebugMessage:data];
    [self logDebugMessage:@"\n--------------------\n"];
}


// UITextFieldDelegate Protocol ------------------------------------------------

// Used to disable the 'Connect' button if there is no text in the host field.
-             (BOOL)textField:(UITextField *)textField 
shouldChangeCharactersInRange:(NSRange)range
            replacementString:(NSString *)string
{
    if (textField == urlField) {
        if ([urlField.text length] == 1 && [string length] == 0) {
            [connectButton setEnabled:NO];
        } else {
            [connectButton setEnabled:YES];
        }
    }

    return YES;
}


// IphoneClientViewController --------------------------------------------------

// Helper function for convering host name strings to an IP address string
- (NSString*) getIPAddress:(NSString*)inputAddress
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    
    struct addrinfo* result = NULL;
    getaddrinfo([inputAddress UTF8String], NULL, &hints, &result);
    
    char outbuf[16];
    memset(outbuf, 0, sizeof(outbuf));
    struct sockaddr_in* sa = (struct sockaddr_in*) result->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, outbuf, sizeof(outbuf));
    freeaddrinfo(result);

    return [NSString stringWithUTF8String:outbuf];
}


- (IBAction) connect:(id)sender
{
    // Dismiss the keyboard.
    [urlField resignFirstResponder];
    [portField resignFirstResponder];

    // Get the host address and port from the input fields.
    NSString* address = [self getIPAddress:urlField.text];
    
    int port = [portField.text intValue];
    if (port == 0 || port == INT_MAX || port == INT_MIN) {
        port = kDefaultPort;
        [portField setText:[NSString stringWithFormat:@"%d", port]];
    }

    NSString* connectAttempt =
        [NSString stringWithFormat:@"Connecting to %@:%d", address, port];
    [self logDebugMessage:connectAttempt];

    // Blocking SSL connect and transfer call.
    SslHelper* matrixSsl =
        [[[SslHelper alloc] initWithIP:address port:port] autorelease];
    [matrixSsl setDelegate:self];
    [matrixSsl connect];
}


// Clears the output field of debug messages.
- (IBAction) clear:(id)sender
{
    [textView setText:@""];
    [clearButton setEnabled:NO];
}


- (void) didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
}


// Implement viewDidLoad to do additional setup after loading the view,
// typically from a nib.
- (void) viewDidLoad
{
    [textView setEditable:NO];
    [textView setFont:[UIFont systemFontOfSize:kDefaultFontSize]];
    [clearButton setEnabled:NO];
    [super viewDidLoad];
}


- (void) viewDidUnload
{
}


- (void) dealloc
{
    [super dealloc];
}


@end
