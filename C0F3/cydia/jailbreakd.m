//
//  ViewController.m
//  v0rtex
//
//  Created by Jake James on 2017-12-07.
//  Copyright © 2017 NOO ONE. NO RIGHTS DESERVED
//  THANK YOU CHEESECAKEUFO FOR THE IDEA AND CYDO

#import "v0rtexJailbreakViewController.h"

#include "v0rtex.h"
#include "kernel.h"
#include "symbols2.h"
#include <sys/stat.h>
#include <sys/spawn.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <sys/dir.h>
#include "patchfinder64.h"

/* CODE IS AWFUL AND I KNOW IT, DO NOT COMPLAIN.
 NOT MY PRIORITY CLEANING IT UP */

extern task_t tfp0;
extern kptr_t kern_ucred;

#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */



uint64_t procForName(char *name) {
    //THANK YOU NINJAPRAWN
    uint64_t proc = rk642(tfp0, find_allproc2());
    printf("\nINFO: proc: %llu", proc);
    while (proc) {
        char comm[40] = {0};
        kread2(proc + 0x26c, comm, 20);
        //uint32_t pid = (uint32_t)rk32_via_tfp0(tfp0, proc + 0x10);
        printf("\n%s's proc: %llu", comm, proc);
        if (strstr(comm, name)) {
            printf("\nINFO: success: process is: %c and proc is : %llu", comm, proc);
            return proc;
        }
        proc = rk642(tfp0, proc);
    }
    return -1;
}
kern_return_t empower_proc(uint64_t proc, uint64_t kern_ucred) {
    uint32_t csflags = rk32_via_tfp02(tfp0, proc  + 0x2a8 /* csflags */);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
    wk322(tfp0, proc  + 0x2a8 /* csflags */, csflags);
    wk642(proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, kern_ucred);

    return KERN_SUCCESS;
}

void startJBD() {
    
    for(;;) {
        //system("echo $(pidof cydo) > /var/mobile/cydopid.txt"); //pls don't complain about awful code I'm lazy
        //const char *pid = [[NSString stringWithContentsOfFile:@"/var/mobile/cydopid.txt" encoding:NSUTF8StringEncoding error:nil] UTF8String];
        //NSLog(@"found pid is: %s", pid);
       // if (pid != NULL && pid != nil && strcmp(pid, "") != 0) {
            uint64_t target_proc = procForName("cydo");
                // if (target_proc == -1) break; TODO: FIX THIS. Interrupts loop
            empower_proc(target_proc, kern_ucred);
            
        }
    }
//}


