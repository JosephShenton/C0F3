//
//  utilities.m
//  topanga
//
//  Created by Abraham Masri on 12/16/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//  Most functions here are by @xerub
//

#include <dirent.h>
#include <mach/mach.h>
#include <objc/runtime.h>

#include "utilities.h"

#import <Foundation/Foundation.h>

@interface LSApplicationWorkspace : NSObject
+ (id) defaultWorkspace;
- (BOOL) registerApplication:(id)application;
- (BOOL) unregisterApplication:(id)application;
- (BOOL) invalidateIconCache:(id)bundle;
- (BOOL) registerApplicationDictionary:(id)application;
- (BOOL) installApplication:(id)application withOptions:(id)options;
- (BOOL) _LSPrivateRebuildApplicationDatabasesForSystemApps:(BOOL)system internal:(BOOL)internal user:(BOOL)user;
@end

Class lsApplicationWorkspace = NULL;
LSApplicationWorkspace* workspace = NULL;

void uicache(void) {
    

    if(lsApplicationWorkspace == NULL || workspace == NULL) {
        lsApplicationWorkspace = (objc_getClass("LSApplicationWorkspace"));
        workspace = [lsApplicationWorkspace performSelector:@selector(defaultWorkspace)];
    }

    if ([workspace respondsToSelector:@selector(_LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:)]) {
        if (![workspace _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:NO])
            printf("[ERROR]: failed to rebuild application databases\n");
        
    }
    
    if ([workspace respondsToSelector:@selector(invalidateIconCache:)]) {
        [workspace invalidateIconCache:nil];
    }
    
    
}

mach_port_t tfp0 = MACH_PORT_NULL;

size_t
kread(uint64_t where, void *p, size_t size)
{
    
    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }
    
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        
        if (rv || sz == 0) {
            printf("[ERROR]: error reading buffer at @%p (where: %llx)\n", (void *)(offset + where), where);
            break;
        }
        offset += sz;
    }
    return offset;
}

uint64_t
kread_uint64(uint64_t where)
{
    uint64_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

uint32_t
kread_uint32(uint64_t where)
{
    uint32_t value = 0;
    size_t sz = kread(where, &value, sizeof(value));
    return (sz == sizeof(value)) ? value : 0;
}

size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    
    if(tfp0 == MACH_PORT_NULL) {
        printf("[ERROR]: tfp0's port is null!\n");
    }
    
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            printf("[ERROR]: error copying buffer into region: @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

size_t
kwrite_uint64(uint64_t where, uint64_t value)
{
    return kwrite(where, &value, sizeof(value));
}

size_t
kwrite_uint32(uint64_t where, uint32_t value)
{
    return kwrite(where, &value, sizeof(value));
}

uint64_t
kalloc_uint64(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

