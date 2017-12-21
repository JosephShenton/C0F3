//
//  asyncJailbreakViewController.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "asyncJailbreakViewController.h"
#include <stdio.h>
#include "kmem.h"

@interface asyncJailbreakViewController ()

@end

@implementation asyncJailbreakViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    for (int i = 0; i<0xff; i++) {
        rk64(0xFFFFFFF007004000 + i*0x100000);
    }
}

- (void)didReceiveMemoryWarning {
    printf("******* received memory warning! ***********\n");
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
