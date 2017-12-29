//
//  v0rtexJailbreakViewController.m
//  C0F3
//
//  Created by Joseph on 21/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "v0rtexJailbreakViewController.h"
#include "v0rtex.h"
#include "kernel.h"
#include "symbols2.h"
#include "root-rw.h"
#include "libjb.h"
#include "patchfinder64.h"
#include "v0rtex.h"
#include "amfi.h"
#include <sys/spawn.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <sys/dir.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>

@interface v0rtexJailbreakViewController ()

@end

@implementation v0rtexJailbreakViewController

task_t tfp0;
kptr_t kslide;
kptr_t kern_ucred;
kptr_t self_proc;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    // Log current device and version info
    NSString *ver = [[NSProcessInfo processInfo] operatingSystemVersionString];
    struct utsname u;
    uname(&u);
    
    [self writeText:[NSString stringWithFormat:@"found %s on iOS %@", u.machine, ver]];
    
    // Attempt to init our offsets
    // Disable the run button if no offsets were found
    if (!init_symbols()) {
        [self writeText:@"Device not supported."];
//        [self.sploitButton setHidden:TRUE];
        [self performSegueWithIdentifier:@"unknown_segue" sender:self];
        return;
    }
    
    [self writeText:@"> ready."];
    [self runSploit];
}

- (void)runSploit {
    
    // Run v0rtex
    
    [self writeText:@"> running exploit..."];
    
    tfp0 = MACH_PORT_NULL;
    kslide = 0;
    kern_ucred = 0;
    self_proc = 0;
    
    kern_return_t ret = v0rtex(&tfp0, &kslide, &kern_ucred, &self_proc);
    
    if (ret != KERN_SUCCESS) {
        [self writeText:@"ERROR: exploit failed"];
        return;
    }
    
    [self writeText:@"exploit succeeded!"];
    
    printf("got val for self_proc = 0x%llx \n", self_proc);
    printf("got val for kern_ucred = 0x%llx \n", kern_ucred);
    
    {
        // set up stuff
        init_patchfinder(tfp0, kslide + 0xFFFFFFF007004000, NULL);
        init_amfi(tfp0);
        init_kernel(tfp0);
    }
    
    {
        // Remount '/' as r/w
        int remount = mount_root(tfp0, kslide);
        LOG("remount: %d", remount);
        if (remount != 0) {
            [self writeText:[NSString stringWithFormat:@"ERROR: failed to remount '/' as r/w (%d)", remount]];
            return;
        }
        [self writeText:@"remounted '/' as r/w"];
    }
    
    {
        // Check we have '/' access
        bool rootAccess = can_write_root();
        [self writeText:[NSString stringWithFormat:@"can write to root: %@", rootAccess ? @"yes" : @"no"]];
        LOG("has root access: %s", rootAccess ? "yes" : "no");
    }
    
    {
        // create v0rtex dirs
        mkdir("/C0F3", 0777);
        mkdir("/C0F3/bins", 0777);
        mkdir("/C0F3/logs", 0777);
        
    }
    
    // init filemanager n bundlepath
    NSFileManager *fileMgr = [NSFileManager defaultManager];
    NSString *bundlePath = [NSString stringWithFormat:@"%s", bundle_path()];
    
    {
        // remove old files
        NSLog(@"removing old files...");
        [fileMgr removeItemAtPath:@"/C0F3/bins" error:nil];
        [fileMgr removeItemAtPath:@"/C0F3/bootstrap.tar" error:nil];
        [fileMgr removeItemAtPath:@"/C0F3/bootstrap2.tar" error:nil];
        [fileMgr removeItemAtPath:@"/C0F3/dropbear" error:nil];
        [fileMgr removeItemAtPath:@"/C0F3/start.sh" error:nil];
        [fileMgr removeItemAtPath:@"/C0F3/tar" error:nil];
        [fileMgr removeItemAtPath:@"/bin/sh" error:nil];
        
        // copy in all our bins
        NSLog(@"copying bins...");
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/bootstrap.tar"]
                         toPath:@"/C0F3/bootstrap.tar" error: nil];
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/dropbear"]
                         toPath:@"/C0F3/dropbear" error:nil];
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/tar"]
                         toPath:@"/C0F3/tar" error:nil];
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/bash"]
                         toPath:@"/bin/sh" error:nil];
        
        // make sure all our bins have perms
        chmod("/C0F3/dropbear", 0777);
        chmod("/C0F3/tar", 0777);
        chmod("/bin/sh", 0777);
        
        // create dir's and files for dropbear
        mkdir("/etc", 0777);
        mkdir("/etc/dropbear", 0777);
        mkdir("/var", 0777);
        mkdir("/var/log", 0777);
        FILE *lastLog = fopen("/var/log/lastlog", "ab+");
        fclose(lastLog);
        
        [self writeText:@"copied bins and set up envrionment"];
    }
    
    {
        // fuck up amfi
        inject_trust("/bin/sh");
        inject_trust("/C0F3/dropbear");
        inject_trust("/C0F3/tar");
    }
    
    {
        // extract bootstrap.tar
        execprog(0, "/C0F3/tar", (const char **)&(const char*[]){ "/C0F3/tar", "-xf", "/C0F3/bootstrap.tar", "-C", "/C0F3", NULL });
        
        // sign all the binaries
        trust_files("/C0F3/bins");
        
        [self writeText:@"extracted and signed all bins"];
    }
    
    {
        // Launch dropbear
        NSLog(@"MAKE SURE TO FIRST RUN 'export PATH=$PATH:/C0F3/bins' WHEN FIRST CONNECTING TO SSH");
        execprog(kern_ucred, "/C0F3/dropbear", (const char**)&(const char*[]){
            "/C0F3/dropbear", "-R", "-E", "-m", "-S", "/", NULL
        });
        [self writeText:@"dropbear launched"];
    }
    
    // Done.
    [self writeText:@"\n done."];
}

- (void)writeText:(NSString *)text {
//    self.outputView.text = [self.outputView.text stringByAppendingString:[text stringByAppendingString:@"\n"]];
    NSLog(@"%@", text);
}

// creds to stek on this one
int execprog(uint64_t kern_ucred, const char *prog, const char* args[]) {
    if (args == NULL) {
        args = (const char **)&(const char*[]){ prog, NULL };
    }
    
    const char *logfile = [NSString stringWithFormat:@"/C0F3/logs/%@-%lu",
                           [[NSMutableString stringWithUTF8String:prog] stringByReplacingOccurrencesOfString:@"/" withString:@"_"],
                           time(NULL)].UTF8String;
    printf("Spawning [ ");
    for (const char **arg = args; *arg != NULL; ++arg) {
        printf("'%s' ", *arg);
    }
    printf("] to logfile [ %s ] \n", logfile);
    
    int rv;
    posix_spawn_file_actions_t child_fd_actions;
    if ((rv = posix_spawn_file_actions_init (&child_fd_actions))) {
        perror ("posix_spawn_file_actions_init");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_addopen (&child_fd_actions, STDOUT_FILENO, logfile,
                                                O_WRONLY | O_CREAT | O_TRUNC, 0666))) {
        perror ("posix_spawn_file_actions_addopen");
        return rv;
    }
    if ((rv = posix_spawn_file_actions_adddup2 (&child_fd_actions, STDOUT_FILENO, STDERR_FILENO))) {
        perror ("posix_spawn_file_actions_adddup2");
        return rv;
    }
    
    pid_t pd;
    if ((rv = posix_spawn(&pd, prog, &child_fd_actions, NULL, (char**)args, NULL))) {
        printf("posix_spawn error: %d (%s)\n", rv, strerror(rv));
        return rv;
    }
    
    printf("process spawned with pid %d \n", pd);
    
#define CS_GET_TASK_ALLOW       0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER            0x0000008    /* has installer entitlement      */
#define CS_HARD                 0x0000100    /* don't load invalid pages       */
#define CS_RESTRICT             0x0000800    /* tell dyld to treat restricted  */
#define CS_PLATFORM_BINARY      0x4000000    /* this is a platform binary      */
    
    /*
     1. read 8 bytes from proc+0x100 into self_ucred
     2. read 8 bytes from kern_ucred + 0x78 and write them to self_ucred + 0x78
     3. write 12 zeros to self_ucred + 0x18
     */
    
    // find_allproc will crash, currently
    // please fix
    if (kern_ucred != 0) {
        int tries = 3;
        while (tries-- > 0) {
            sleep(1);
            uint64_t proc = rk64(kslide + 0xFFFFFFF0075E66F0);
            while (proc) {
                uint32_t pid = rk32(proc + 0x10);
                if (pid == pd) {
                    uint32_t csflags = rk32(proc + 0x2a8);
                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
                    wk32(proc + 0x2a8, csflags);
                    tries = 0;
                    
                    // i don't think this bit is implemented properly
                    uint64_t self_ucred = rk64(proc + 0x100);
                    uint32_t selfcred_temp = rk32(kern_ucred + 0x78);
                    wk32(self_ucred + 0x78, selfcred_temp);
                    
                    for (int i = 0; i < 12; i++) {
                        wk32(self_ucred + 0x18 + (i * sizeof(uint32_t)), 0);
                    }
                    
                    printf("gave elevated perms to pid %d \n", pid);
                    
                    // original stuff, rewritten above using v0rtex stuff
                    // kcall(find_copyout(), 3, proc+0x100, &self_ucred, sizeof(self_ucred));
                    // kcall(find_bcopy(), 3, kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t));
                    // kcall(find_bzero(), 2, self_ucred + 0x18, 12);
                    break;
                }
                proc = rk64(proc);
            }
        }
    }
    
    int status;
    waitpid(pd, &status, 0);
    printf("'%s' exited with %d (sig %d)\n", prog, WEXITSTATUS(status), WTERMSIG(status));
    
    char buf[65] = {0};
    int fd = open(logfile, O_RDONLY);
    if (fd == -1) {
        perror("open logfile");
        return 1;
    }
    
    printf("contents of %s: \n ------------------------- \n", logfile);
    while(read(fd, buf, sizeof(buf) - 1) == sizeof(buf) - 1) {
        printf("%s", buf);
    }
    printf("%s", buf);
    printf("\n-------------------------\n");
    
    close(fd);
    remove(logfile);
    
    return 0;
}

int execprog_clean(uint64_t kern_ucred, const char *prog, const char* args[]) {
    if (args == NULL) {
        args = (const char **)&(const char*[]){ prog, NULL };
    }
    
    int rv;
    pid_t pd;
    if ((rv = posix_spawn(&pd, prog, NULL, NULL, (char**)args, NULL))) {
        printf("posix_spawn error: %d (%s)\n", rv, strerror(rv));
        return rv;
    }
    
#define CS_GET_TASK_ALLOW       0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER            0x0000008    /* has installer entitlement      */
#define CS_HARD                 0x0000100    /* don't load invalid pages       */
#define CS_RESTRICT             0x0000800    /* tell dyld to treat restricted  */
#define CS_PLATFORM_BINARY      0x4000000    /* this is a platform binary      */
    
    /*
     1. read 8 bytes from proc+0x100 into self_ucred
     2. read 8 bytes from kern_ucred + 0x78 and write them to self_ucred + 0x78
     3. write 12 zeros to self_ucred + 0x18
     */
    
    if (kern_ucred != 0) {
        int tries = 3;
        while (tries-- > 0) {
            sleep(1);
            // this needs to be moved to an offset VVVVVVVVVVVVV
            uint64_t proc = rk64(kslide + 0xFFFFFFF0075E66F0);
            while (proc) {
                uint32_t pid = rk32(proc + 0x10);
                if (pid == pd) {
                    uint32_t csflags = rk32(proc + 0x2a8);
                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
                    wk32(proc + 0x2a8, csflags);
                    tries = 0;
                    
                    // i don't think this bit is implemented properly
                    uint64_t self_ucred = rk64(proc + 0x100);
                    uint32_t selfcred_temp = rk32(kern_ucred + 0x78);
                    wk32(self_ucred + 0x78, selfcred_temp);
                    
                    for (int i = 0; i < 12; i++) {
                        wk32(self_ucred + 0x18 + (i * sizeof(uint32_t)), 0);
                    }
                    
                    // original stuff, rewritten above using v0rtex stuff
                    // kcall(find_copyout(), 3, proc+0x100, &self_ucred, sizeof(self_ucred));
                    // kcall(find_bcopy(), 3, kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t));
                    // kcall(find_bzero(), 2, self_ucred + 0x18, 12);
                    break;
                }
                proc = rk64(proc);
            }
        }
    }
    
    int status;
    waitpid(pd, &status, 0);
    return status;
}

void read_file(const char *path) {
    char buf[65] = {0};
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open path");
        return;
    }
    
    printf("contents of %s: \n ------------------------- \n", path);
    while(read(fd, buf, sizeof(buf) - 1) == sizeof(buf) - 1) {
        printf("%s", buf);
    }
    printf("%s", buf);
    printf("\n-------------------------\n");
    
    close(fd);
}

bool can_write_root() {
    FILE *f = fopen("/file123.txt", "w");
    return f != 0;
}

char* bundle_path() {
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesURL = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char* path = malloc(len);
    
    CFURLGetFileSystemRepresentation(resourcesURL, TRUE, (UInt8*)path, len);
    
    return path;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
