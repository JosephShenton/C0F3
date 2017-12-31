#include "libjb.h"
#include "../kernel.h"
#include <mach/mach.h>
#include "patchfinder64.h"
#include <stdio.h>
#include <stdlib.h>
#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/stat.h>

task_t taskfp0;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);



void kwrite232(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite2(where, &_what, sizeof(uint32_t));
}


void kwrite264(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite2(where, &_what, sizeof(uint64_t));
}

static uint64_t kalloc(vm_size_t size){
  //  printf("taskfp0: %d", taskfp0);
        mach_vm_address_t address = 0;
        mach_vm_allocate(taskfp0, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
        return address;
    }

int cp2(const char *to, const char *from)
{
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;
    
    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;
    
    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;
    
    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;
        
        do {
            nwritten = write(fd_to, out_ptr, nread);
            
            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }
    
    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);
        
        /* Success! */
        return 0;
    }
    
out_error:
    saved_errno = errno;
    
    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);
    
    errno = saved_errno;
    return -1;
}

int patch_amfi(task_t tfpzero, uint64_t kslide, bool isv0rtex, bool hastweaks) {
    taskfp0 = tfpzero;
    //printf("taskfp0: %d", taskfp0);
    init_patchfinder(taskfp0, 0xfffffff007004000 + kslide, NULL); //start patchfinder
    uint64_t trust_chain = find_trustcache2(); //find trust cache
    uint64_t amficache = find_amficache2(); //find amficache
    printf("trust_chain = 0x%llx\n", trust_chain);
    printf("amficache = 0x%llx\n", amficache);
    struct trust_mem mem;
    mem.next = rk642(taskfp0, trust_chain);
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    
    //USAGE:
    //call grab_hashes to trust a binary
    //EXAMPLE: grab_hashes("/usr/bin", kread22, amficache, mem.next)
    
    //first amfi patch
    
    if (isv0rtex) {
        
        printf("v0rtex rv = %d, numhash = %d\n", grab_hashes("/v0rtex", kread2, amficache, mem.next), numhash); //WHY ON EARTH THIS WASN'T HERE
        printf("bin rv = %d, numhash = %d\n", grab_hashes("/bin", kread2, amficache, mem.next), numhash);
        printf("usr rv = %d, numhash = %d\n", grab_hashes("/usr", kread2, amficache, mem.next), numhash);
        printf("sbin rv = %d, numhash = %d\n", grab_hashes("/sbin", kread2, amficache, mem.next), numhash);
        printf("dpkg rv = %d, numhash = %d\n", grab_hashes("/.dpkg/dpkg", kread2, amficache, mem.next), numhash);
        
        if (hastweaks) {
            NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
            NSString *documentsDirectory = [paths objectAtIndex:0];
            
            NSString *filePath = [NSString stringWithFormat:@"%@/%@", documentsDirectory,@"tweak.deb"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            NSString *firstcmd = [NSString stringWithFormat:@"dpkg -e %@ /v0rtex", filePath];
            system([firstcmd UTF8String]);
                printf("postinst rv = %d, numhash = %d\n", grab_hashes("/v0rtex", kread2, amficache, mem.next), numhash);
            }
        }
        
    }
    //second amfi patch
    else {
    /* printf("usrbin rv = %d, numhash = %d\n", grab_hashes("/usr/bin", kread22, amficache, mem.next), numhash);
   printf("localbin rv = %d, numhash = %d\n", grab_hashes("/usr/local/bin", kread22, amficache, mem.next), numhash);
    printf("bin rv = %d, numhash = %d\n", grab_hashes("/bin", kread22, amficache, mem.next), numhash);
    printf("sbin rv = %d, numhash = %d\n", grab_hashes("/sbin", kread22, amficache, mem.next), numhash);
        printf("Apps rv = %d, numhash = %d\n", grab_hashes("/Applications", kread22, amficache, mem.next), numhash);
    printf("usrlib rv = %d, numhash = %d\n", grab_hashes("/usr/lib", kread22, amficache, mem.next), numhash);
        printf("usrlibexec rv = %d, numhash = %d\n", grab_hashes("/usr/libexec", kread22, amficache, mem.next), numhash);
    printf("substratelib rv = %d, numhash = %d\n", grab_hashes("/Library/Frameworks/CydiaSubstrate.framework", kread22, amficache, mem.next), numhash);
    printf("dylibs rv = %d, numhash = %d\n", grab_hashes("/Library/MobileSubstrate", kread22, amficache, mem.next), numhash);*/
        printf("usr rv = %d, numhash = %d\n", grab_hashes("/usr", kread2, amficache, mem.next), numhash);
        printf("bin rv = %d, numhash = %d\n", grab_hashes("/bin", kread2, amficache, mem.next), numhash);
        printf("sbin rv = %d, numhash = %d\n", grab_hashes("/sbin", kread2, amficache, mem.next), numhash);
        printf("Apps rv = %d, numhash = %d\n", grab_hashes("/Applications", kread2, amficache, mem.next), numhash);
        printf("Library rv = %d, numhash = %d\n", grab_hashes("/Library", kread2, amficache, mem.next), numhash);
        
       // printf("dylibs rv = %d, numhash = %d\n", grab_hashes("/Library/MobileSubstrate", kread22, amficache, mem.next), numhash);
        
    
    }
    
    size_t length = (sizeof(mem) + numhash * 20 + 0xFFFF) & ~0xFFFF;
    uint64_t kernel_trust = kalloc(length);
    printf("alloced: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    mem.count = numhash;
    kwrite2(kernel_trust, &mem, sizeof(mem));
    kwrite2(kernel_trust + sizeof(mem), allhash, numhash * 20);
    kwrite264(trust_chain, kernel_trust);
    
    if (hastweaks && !isv0rtex) {
        system("/usr/libexec/cydia/firmware.sh");
        
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *documentsDirectory = [paths objectAtIndex:0];
        
        NSString *filePath = [NSString stringWithFormat:@"%@/%@", documentsDirectory,@"tweak.deb"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            NSLog(@"\npath = %@ \n", filePath);
            NSString *secondcmd = [NSString stringWithFormat:@"dpkg --ignore-depends preferenceloader -i %@", filePath];
            system([secondcmd UTF8String]); //install
            sleep(2);
            [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil]; //clean up
        }
    }
    
    if (!isv0rtex) {
    free(allhash);
    free(allkern);
    free(amfitab);
    }
    //this is the old code
    //char *tt = "echo 'dlopen(\"/Library/MobileSubstrate/MobileSubstrate.dylib\", RTLD_LAZY)'| cycript -p SpringBoard";
    //printf("\n THIS CYC: %s \n", tt);
    //system(tt);
    //system("launchctl load /Library/LaunchDaemons/*");
    
    return 0;
}
