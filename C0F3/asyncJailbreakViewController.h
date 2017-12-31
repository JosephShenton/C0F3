//
//  asyncJailbreakViewController.h
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface asyncJailbreakViewController : UIViewController
pid_t get_pid_for_name(char *proc_name, int spawned);
@end
