//
//  fateViewController.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "fateViewController.h"

@interface fateViewController ()

@end

@implementation fateViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        //Here your non-main thread.
        [NSThread sleepForTimeInterval:3.0f];
        dispatch_async(dispatch_get_main_queue(), ^{
            //Here you returns to main thread.
            if (SYSTEM_VERSION_LESS_THAN(@"10.0")) {
                [self performSegueWithIdentifier:@"unknown_segue" sender:self];
            }
            
            if (SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"10.3.3")) {
                [self performSegueWithIdentifier:@"v0rtex_found_segue" sender:self];
            }
            
            if (SYSTEM_VERSION_LESS_THAN(@"11.0")) {
                [self performSegueWithIdentifier:@"unknown_segue" sender:self];
            }
            
            if (SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.1.2")) {
                [self performSegueWithIdentifier:@"async_found_segue" sender:self];
            }
            
            if (SYSTEM_VERSION_GREATER_THAN(@"11.1.2")) {
                [self performSegueWithIdentifier:@"unknown_segue" sender:self];
            }
        });
    });
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
