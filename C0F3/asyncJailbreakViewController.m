//
//  asyncJailbreakViewController.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "asyncJailbreakViewController.h"
#include "async_wake.h"
#include "fun.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include "kmem.h"

extern int MISValidateSignatureAndCopyInfo (CFStringRef File, CFDictionaryRef Opts, NSDictionary *Info);
extern CFStringRef MISCopyErrorStringForErrorCode(int Error);

typedef int (*t)(CFStringRef f, CFDictionaryRef o, NSDictionary**    I);
typedef CFStringRef (*w)(int e);

@interface asyncJailbreakViewController ()

@end

@implementation asyncJailbreakViewController

- (void)viewDidLoad {
    [super viewDidLoad];
//    for (int i = 0; i<0xff; i++) {
//        rk64(0xFFFFFFF007004000 + i*0x100000);
//    }
    mach_port_t user_client;
    mach_port_t tfp0 = get_tfp0(&user_client);
    
    let_the_fun_begin(tfp0, user_client);
    
    NSLog(@" ♫ KPP never bothered me anyway... ♫ ");
    
    //    [@"test" writeToFile:@"/testingfiles" atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    
    // the app seems to remain even after stopped by xcode - we'll just force it to quit
    kill(getpid(), SIGKILL);
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

@end
