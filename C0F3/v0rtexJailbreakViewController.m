//
//  v0rtexJailbreakViewController.m
//  v0rtex
//
//  Created by Sticktron on 2017-12-07.
//  Copyright © 2017 Sticktron. All rights reserved.
//

#import "v0rtexJailbreakViewController.h"

#include "v0rtex.h"
#include "kernel.h"
#include "symbols2.h"
#include "root-rw.h"
#include "the_super_fun_part/amfi.h"
#include <sys/stat.h>
#include <sys/spawn.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <sys/dir.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>

task_t tfp0;
kptr_t kslide;
kptr_t kern_ucred;
kptr_t self_proc;

//get executable path

char* bundle_path() {
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesURL = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char* path = malloc(len);
    
    CFURLGetFileSystemRepresentation(resourcesURL, TRUE, (UInt8*)path, len);
    
    return path;
}

//execute
//thanks PsychoTea and whoever worked on his fork of v0rtex

int execprog(task_t tfp0, uint64_t kslide, uint64_t kern_ucred, const char *prog, const char* args[]) {
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
            uint64_t proc = rk642(tfp0, kslide + 0xFFFFFFF0075E66F0);
            while (proc) {
                uint32_t pid = rk32_via_tfp02(tfp0, proc + 0x10);
                if (pid == pd) {
                    uint32_t csflags = rk32_via_tfp02(tfp0, proc + 0x2a8);
                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
                    wk322(tfp0, proc + 0x2a8, csflags);
                    tries = 0;
                    
                    // i don't think this bit is implemented properly
                    uint64_t self_ucred = rk642(tfp0, proc + 0x100);
                    uint32_t selfcred_temp = rk32_via_tfp02(tfp0, kern_ucred + 0x78);
                    wk322(tfp0, self_ucred + 0x78, selfcred_temp);
                    
                    for (int i = 0; i < 3; i++) {
                        wk322(tfp0, self_ucred + 0x18 + (i * sizeof(uint32_t)), 0);
                    }
                    
                    printf("gave elevated perms to pid %d \n", pid);
                    
                    // original stuff, rewritten above using v0rtex stuff
                    // kcall(find_copyout(), 3, proc+0x100, &self_ucred, sizeof(self_ucred));
                    // kcall(find_bcopy(), 3, kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t));
                    // kcall(find_bzero(), 2, self_ucred + 0x18, 12);
                    break;
                }
                proc = rk642(tfp0, proc);
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

int execprog_clean(task_t tfp0, uint64_t kslide, uint64_t kern_ucred, const char *prog, const char* args[]) {
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
            uint64_t proc = rk642(tfp0, kslide + 0xFFFFFFF0075E66F0);
            while (proc) {
                uint32_t pid = rk32_via_tfp02(tfp0, proc + 0x10);
                if (pid == pd) {
                    uint32_t csflags = rk32_via_tfp02(tfp0, proc + 0x2a8);
                    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
                    wk322(tfp0, proc + 0x2a8, csflags);
                    tries = 0;
                    
                    // i don't think this bit is implemented properly
                    uint64_t self_ucred = rk642(tfp0, proc + 0x100);
                    uint32_t selfcred_temp = rk32_via_tfp02(tfp0, kern_ucred + 0x78);
                    wk322(tfp0, self_ucred + 0x78, selfcred_temp);
                    
                    for (int i = 0; i < 3; i++) {
                        wk322(tfp0, self_ucred + 0x18 + (i * sizeof(uint32_t)), 0);
                    }
                    
                    // original stuff, rewritten above using v0rtex stuff
                    // kcall(find_copyout(), 3, proc+0x100, &self_ucred, sizeof(self_ucred));
                    // kcall(find_bcopy(), 3, kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t));
                    // kcall(find_bzero(), 2, self_ucred + 0x18, 12);
                    break;
                }
                proc = rk642(tfp0, proc);
            }
        }
    }
    
    int status;
    waitpid(pd, &status, 0);
    return status;
}
@interface v0rtexJailbreakViewController ()
@property (weak, nonatomic) IBOutlet UITextView *outputView;
@property (weak, nonatomic) IBOutlet UIButton *sploitButton;
@end

@implementation v0rtexJailbreakViewController

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
<<<<<<< HEAD
        [self performSegueWithIdentifier:@"unknown_segue_2" sender:self];
=======
        [self performSegueWithIdentifier:@"unknown_segue" sender:self];
>>>>>>> master
        return;
    }
    
    [self writeText:@"> ready."];
    // UIAlertController * alertController = [UIAlertController alertControllerWithTitle: @"Install deb"
    //                                                                           message: @"If you want to install a deb, do it now, otherwise leave this blank"
    //                                                                    preferredStyle:UIAlertControllerStyleAlert];
    // [alertController addTextFieldWithConfigurationHandler:^(UITextField *textField) {
    //     textField.placeholder = @"deb link";
    //     textField.keyboardType = UIKeyboardTypeDefault;
    // }];
    
    // [alertController addAction:[UIAlertAction actionWithTitle:@"Continue" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
    //     NSArray * textfields = alertController.textFields;
    //     UITextField * namefield = textfields[0];
    //     NSLog(@"%@",namefield.text);
    
    //     NSURL  *url = [NSURL URLWithString:namefield.text];
    //     NSData *urlData = [NSData dataWithContentsOfURL:url];//download deb
    //     if (urlData)
    //     {
    //         NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    //         NSString *documentsDirectory = [paths objectAtIndex:0];
    //         NSString *filePath = [NSString stringWithFormat:@"%@/%@", documentsDirectory,@"tweak.deb"];
    //         [urlData writeToFile:filePath atomically:YES];//save it
    //         sleep(2);
    //     }
    //     [self runsploit];
    
    // }]];
    // [self presentViewController:alertController animated:YES completion:nil];
    [self runsploit];
}


- (void)runsploit{
    
    // Run v0rtex
    [self writeText:@"> running exploit..."];
    
    tfp0 = MACH_PORT_NULL;
    kslide = 0;
    kern_ucred = 0;
    self_proc = 0;
    
    kern_return_t ret = v0rtex(NULL, NULL, &tfp0, &kslide, &kern_ucred, &self_proc);
    
    if (ret != KERN_SUCCESS) {
        [self writeText:@"ERROR: exploit failed"];
        return;
    }
    
    [self writeText:@"exploit succeeded!"];
    
    
    // Write a test file to var
    
    [self writeText:@"writing test file..."];
    
    extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
    uint32_t magic = 0;
    mach_vm_size_t sz = sizeof(magic);
    ret = mach_vm_read_overwrite(tfp0, 0xfffffff007004000 + kslide, sizeof(magic), (mach_vm_address_t)&magic, &sz);
    LOG("mach_vm_read_overwrite: %x, %s", magic, mach_error_string(ret));
    
    FILE *varF = fopen("/var/mobile/test.txt", "w");
    LOG("var file: %p", varF);
    if (varF == 0) {
        [self writeText:@"ERROR: failed to write test var file"];
        return;
    }
    
    [self writeText:@"wrote test var file!"];
    [self writeText:[NSString stringWithFormat:@"/var/mobile/test.txt (%p)", varF]];
    
    
    // Remount '/' as r/w
    
    int remountOutput = mount_root(tfp0, kslide);
    LOG("remount: %d", remountOutput);
    if (remountOutput != 0) {
        [self writeText:@"ERROR: failed to remount '/' as r/w"];
        //  return;
    }
    
    [self writeText:@"remounted '/' as r/w"];
    
    
    // Write a test file to root
    
    [self writeText:@"writing test root file..."];
    
    FILE *rootF = fopen("/test.txt", "w");
    LOG("root file: %p", rootF);
    if (rootF == 0) {
        [self writeText:@"ERROR: failed to write root test file"];
        // return;
    }
    
    [self writeText:@"wrote test root file!"];
    [self writeText:[NSString stringWithFormat:@"/test.txt (%p)", rootF]];
    
    
    
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
        
        // create v0rtex dirs
        mkdir("/C0F3", 0777);
        //mkdir("/C0F3/bins", 0777);
        mkdir("/C0F3/logs", 0777);
        
        NSError *error;
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/bootstrap2.tar"]
                         toPath:@"/C0F3/bootstrap.tar" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/dropbear2"]
                         toPath:@"/C0F3/dropbear" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/tar2"]
                         toPath:@"/C0F3/tar" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/extrainst_"]
                         toPath:@"/C0F3/extrainst_" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        [fileMgr removeItemAtPath:@"/usr/libexec/cydia/cydo" error:nil];
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/cydo"]
                         toPath:@"/usr/libexec/cydia/cydo" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        [fileMgr copyItemAtPath:[bundlePath stringByAppendingString:@"/bash"]
                         toPath:@"/bin/sh" error: &error];
        if (error) NSLog(@"Error: %@", error);
        
        // make sure all our bins have perms
        chmod("/C0F3/dropbear", 0777);
        chmod("/C0F3/tar", 0777);
        chmod("/bin/sh", 0777);
        chmod("/C0F3/extrainst_", 0777);
        chmod("/usr/libexec/cydia/cydo", 0777);
        
        // create dir's and files for dropbear
        mkdir("/etc", 0777);
        mkdir("/etc/dropbear", 0777);
        mkdir("/var", 0777);
        mkdir("/var/log", 0777);
        FILE *lastLog = fopen("/var/log/lastlog", "ab+");
        fclose(lastLog);
    }
    
    {
        //first amfi patch: for v0rtex files
        int amfi = patch_amfi(tfp0, kslide, YES, YES);
        [self writeText:[NSString stringWithFormat:@"v0rtex amfi: %d", amfi]];
    }
    
    {
        //installed?
        int f = open("/.installed_v0rtexb4", O_RDONLY);
        
        if (f == -1) {
            system("rm -rf /var/lib/dpkg && ln -sf /.dpkg/dpkg /var/lib/dpkg"); //if we have an older version remove it
            // extract bootstrap.tar
            execprog(tfp0, kslide, 0, "/C0F3/tar", (const char **)&(const char*[]){ "/C0F3/tar", "--preserve-permissions", "--no-overwrite-dir", "-xvf", "/C0F3/bootstrap.tar", "-C", "/", NULL });
            
            //trust all the binaries
            
            open("/.installed_v0rtexb4", O_RDWR|O_CREAT);
            open("/.cydia_no_stash",O_RDWR|O_CREAT);
            
            //system("/usr/bin/uicache");
            system("killall -SIGSTOP cfprefsd");
            NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
            [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
            [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
            system("killall -9 cfprefsd");
        }
    }
    
    {
        
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
        chmod("/private/var/mobile/Library/Preferences/com.apple.springboard.plist", 0600); //rw/-/-
        chown("/private/var/mobile/Library/Preferences/com.apple.springboard.plist", 501, 501); //mobile
        
    }
    
    {
        //second amfi patch, binaries, tweaks & Cydia
        int amfi2 = patch_amfi(tfp0, kslide, NO, YES);
        [self writeText:[NSString stringWithFormat:@"cydia amfi: %d", amfi2]];
        system("/C0F3/extrainst_"); //taken from substrate, patched the move.sh string so it doesn't stash
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSLog(@"cleaning up...");
            [fileMgr removeItemAtPath:@"/C0F3/bins" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/bootstrap.tar" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/bootstrap2.tar" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/dropbear" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/start.sh" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/tar" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/extrainst_" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/postinst" error:nil];
            [fileMgr removeItemAtPath:@"/C0F3/prerm" error:nil];
            
            chmod("/Library/LaunchDaemons/dropbear.plist", 0644);
            chown("/Library/LaunchDaemons/dropbear.plist", 0, 0);
            chmod("/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", 0644);
            chown("/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", 0, 0);
            chmod("/Library/LaunchDaemons/0.reload.plist", 0644);
            chown("/Library/LaunchDaemons/0.reload.plist", 0, 0);
            system("launchctl load /Library/LaunchDaemons/dropbear.plist");
            system("launchctl load /Library/LaunchDaemons/com.saurik.Cydia.Startup.plist");
            system("echo 'string=$(ps aux | grep $1 | grep -v grep | grep -v pidof | grep -v pidsof); list=(${string}); for pid in ${!list[@]}; do ((pid == 1)) && printf \"${list[$pid]}\"; done' > /usr/bin/pidof; chmod 777 /usr/bin/pidof");
            // if ([self.shallrespring isOn]) {
            //     system("echo 'killall SpringBoard' > /usr/libexec/reload");
            // }
            // else {
            system("echo 'killall nothing' > /usr/libexec/reload");
            // }
            // system("echo 'killall SpringBoard' > /usr/libexec/reload");
            // if (self.method.selectedSegmentIndex == 0) {
            //     NSLog(@"doing method 1");
            //     system("printf \"#/bin/bash\\nif [ \\$# -eq \"2\" ]; then\\nkillall_ \\$1 \\$2 && cynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) /Library/MobileSubstrate/MobileSubstrate.dylib\\nelif [ \\$# -eq \"1\" ]; then\\nkillall_ \\$1 && cynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) /Library/MobileSubstrate/MobileSubstrate.dylib\\nfi\" > /usr/bin/killall");
            // }
            // else {
            //     NSLog(@"doing method 2");
            //     system("printf \"#/bin/bash\\nif [ \\$# -eq \"2\" ]; then\\nkillall_ \\$1 \\$2\\nfor i in /Library/MobileSubstrate/DynamicLibraries/*.dylib\\ndo\\ncynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) \\$i\\ndone\\nelif [ \\$# -eq \"1\" ]; then\\nkillall_ \\$1\\nfor i in /Library/MobileSubstrate/DynamicLibraries/*.dylib\\ndo\\ncynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) \\$i\\ndone\\nfi\" > /usr/bin/killall");
            // }
            system("printf \"#/bin/bash\\nif [ \\$# -eq \"2\" ]; then\\nkillall_ \\$1 \\$2\\nfor i in /Library/MobileSubstrate/DynamicLibraries/*.dylib\\ndo\\ncynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) \\$i\\ndone\\nelif [ \\$# -eq \"1\" ]; then\\nkillall_ \\$1\\nfor i in /Library/MobileSubstrate/DynamicLibraries/*.dylib\\ndo\\ncynject \\$(pidof System/Library/CoreServices/SpringBoard.app/SpringBoard) \\$i\\ndone\\nfi\" > /usr/bin/killall");
            
            system("launchctl unload /Library/LaunchDaemons/0.reload.plist");
            system("launchctl load /Library/LaunchDaemons/0.reload.plist");
        });
        
        
    }
    
    
    // Done.
    [self writeText:@""];
    [self writeText:@"done."]; //logging does not work now for now
    sleep(3);
    extern void startJBD(void);
    startJBD();
<<<<<<< HEAD
    [self performSegueWithIdentifier:@"v0rtex_jailbroken" sender:self];
=======
>>>>>>> master
}


- (void)writeText:(NSString *)text {
    //    self.outputView.text = [self.outputView.text stringByAppendingString:[text stringByAppendingString:@"\n"]];
    NSLog(@"%@", text);
}

@end
