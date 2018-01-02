//
//  backwardSegue.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "backwardSegue.h"

@implementation backwardSegue
    -(void) perform {
        
        UIView *preV = ((UIViewController *)self.sourceViewController).view;
        UIView *newV = ((UIViewController *)self.destinationViewController).view;
        
        UIWindow *window = [[[UIApplication sharedApplication] delegate] window];
        newV.center = CGPointMake(preV.center.x - preV.frame.size.width, newV.center.y);
        [window insertSubview:newV aboveSubview:preV];
        
        [UIView animateWithDuration:0.4
                         animations:^{
                             newV.center = CGPointMake(preV.center.x, newV.center.y);
                             preV.center = CGPointMake(preV.center.x + preV.frame.size.width, newV.center.y);}
                         completion:^(BOOL finished){
                             [preV removeFromSuperview];
                             window.rootViewController = self.destinationViewController;
                         }];
    }
@end
