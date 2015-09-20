/**
 *	@file    iphoneClientAppDelegate.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Summary.
 */
#import <UIKit/UIKit.h>

@class IphoneClientViewController;

@interface iphoneClientAppDelegate : NSObject <UIApplicationDelegate>
{
	UIWindow* window;
	IphoneClientViewController* viewController;
}

@property (nonatomic, retain) IBOutlet UIWindow* window;
@property (nonatomic, retain) IBOutlet IphoneClientViewController* viewController;

@end

