//
//  jailbreakd.m
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include "jailbreak.h"
#include "utilities.h"
#include "libjb.h"
#include "kutils.h"
#include "kcall.h"
#include "symbols.h"
#include "kmem.h"
#include "amfi_codesign.h"
#include "patchfinder64_11.h"

#include <errno.h>
#include <dirent.h>

NSMutableArray *allowed_binaries;
NSMutableArray *processed_pids;
uint64_t task_self;


/*
 *  Purpose: scans for new procs (all procs AFTER ours)
 */
void *start_scanning() {
    
    extern uint64_t kern_ucred;

    // uh..
    for(;;) {
        usleep(700000);

        for(NSString *allowed_binary in allowed_binaries) {
            
            char *binary_char_name = strdup([allowed_binary UTF8String]);
            
            NSMutableArray *pids_list = get_pids_list_for_name(binary_char_name);

            for(int i = 0; i < [pids_list count]; i++) {
                
                pid_t binary_pid = (pid_t) [[pids_list objectAtIndex:i] intValue];
                printf("[INFO]: processing pid: %d\n", binary_pid);
                if(binary_pid == -1) continue;
                
                // check if we already empowered the pid
                if([processed_pids containsObject:@(binary_pid)]) {
                    printf("[INFO]: already gave %s power.\n", binary_char_name);
                    continue;
                }
                
                [processed_pids addObject:@(binary_pid)];
                
                printf("[INFO]: %s's pid: %d\n", binary_char_name, binary_pid);
                uint64_t binary_proc = get_proc_for_pid(binary_pid, true);
                if(binary_proc == -1) continue;
                
                printf("[INFO]: %s's proc: %llx\n", binary_char_name, binary_proc);

                // store the original credentials for later
                uint64_t binary_original_cred = kread_uint64(binary_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */);
                
                printf("[INFO]: getting and setting %s's cflags..\n", binary_char_name);
                if(empower_proc(binary_proc) == KERN_SUCCESS) {
                    printf("[INFO]: empowered %s!\n", binary_char_name);
                 
                    // wait till they're empowered then set the old creds back to avoid panics
                    usleep(500000);
                    kwrite_uint64(binary_proc + 0x100 /* KSTRUCT_OFFSET_PROC_UCRED */, binary_original_cred);
                    
                    printf("[INFO]: I've set %s's creds back to original\n", binary_char_name);
                }
            }
        }
        
    }
    

}

/*
 *  Purpose: Any initialization required is done here
 */
void start_jailbreakd(void) {
    
    task_self = task_self_addr();
    processed_pids = [[NSMutableArray alloc] init];
    allowed_binaries = [[NSMutableArray alloc] initWithObjects:@"cydo", @"http", @"https", @"apt", @"apt-get", @"dpkg", @"gpgv", @"mirror", nil];
    
    
    printf("[*]: welcome to jailbreakd\n");
    sleep(1);
    
    printf("[INFO]: scanning for new procs in a separate thread\n");
    start_scanning();
//    pthread_t tid;
//    pthread_create(&tid, NULL, start_scanning, NULL);
    printf("[INFO]: scanner is running!\n");
}
