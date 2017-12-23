//
//  asyncJailbreakViewController.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "asyncJailbreakViewController.h"
#include <stdio.h>
#include <sys/sysctl.h>

#include "async_wake.h"
#include "extra_recipe/patchfinder64_11.h"
#include "symbols.h"
#include "extra_recipe/jailbreak.h"

@interface asyncJailbreakViewController ()

@end

@implementation asyncJailbreakViewController

- (void)viewDidLoad {
    [super viewDidLoad];
 dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        //Here your non-main thread.
        [NSThread sleepForTimeInterval:3.0f];
        dispatch_async(dispatch_get_main_queue(), ^{
            size_t len = 0;
            char *model = malloc(len * sizeof(char));
            sysctlbyname("hw.model", NULL, &len, NULL, 0);
            if (len) {
                sysctlbyname("hw.model", model, &len, NULL, 0);
                printf("[INFO]: model internal name: %s\n", model);
            }
        });
    });
}

- (void)openScheme:(NSString *)scheme {
    UIApplication *application = [UIApplication sharedApplication];
    NSURL *URL = [NSURL URLWithString:scheme];
    
    if ([application respondsToSelector:@selector(openURL:options:completionHandler:)]) {
        [application openURL:URL options:@{}
           completionHandler:^(BOOL success) {
               NSLog(@"Open %@: %d",scheme,success);
           }];
    } else {
        BOOL success = [application openURL:URL];
        NSLog(@"Open %@: %d",scheme,success);
    }
}

- (void)didReceiveMemoryWarning {
    printf("******* received memory warning! ***********\n");
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)panic {
        for (int i = 0; i<0xff; i++) {
            rk64(0xFFFFFFF007004000 + i*0x100000);
        }
}

kern_return_t ret = KERN_SUCCESS;

- (void) kill_backboardd {
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        pid_t backboardd_pid = get_pid_for_name("backboardd", false);
        printf("[INFO]: killing backboardd\n");
        kill(backboardd_pid, SIGKILL);
    });
    
}

- (void) show_post_jailbreak {
    
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        printf("[INFO]: calling post_jailbreak..\n");
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            extern void start_jailbreakd(void);
            start_jailbreakd();
            [self performSegueWithIdentifier:@"async_jailbroken" sender:self];
            //            [self kill_backboardd];
        });
    });
    
}

- (void) show_unpack_bootstrap {
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        
        unpack_bootstrap();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self show_post_jailbreak];
        });
        
    });
    
}

- (IBAction)jailbreak_tapped:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
        
        ret = go();
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            
            extern uint64_t kernel_base;
            extern uint64_t kaslr_slide;
            
            int rv = init_kernel(kernel_base, NULL);
            
            if(rv == 0) {
                
                uint64_t trustcache = find_trustcache();
                uint64_t amficache = find_amficache();
                uint64_t rootvnode = find_rootvnode();
                
                
                if(ret != KERN_SUCCESS) {
                    // FAILED
                    [self performSegueWithIdentifier:@"async_failed_segue" sender:self];
                    return;
                    
                }
                
                [self show_unpack_bootstrap];
            }
            
        });
    });
    
}

@end
