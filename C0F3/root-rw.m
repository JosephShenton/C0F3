//
//  root-rw.m
//  v0rtex
//
//  Created by Ben on 16/12/2017.
//  Copyright © 2017 Sticktron. All rights reserved.
//

#include "root-rw.h"
#include "kernel.h"
#include "symbols2.h"

// For '/' remount (not offsets)
#define KSTRUCT_OFFSET_MOUNT_MNT_FLAG   0x70
//#define KSTRUCT_OFFSET_MOUNT_MNT_FLAG   0xd8
#define KSTRUCT_OFFSET_VNODE_V_UN       0xd8

int mount_root(task_t tfp0, uint64_t kslide) {
    uint64_t _rootnode = OFFSET_ROOT_MOUNT_V_NODE + kslide;
    uint64_t rootfs_vnode = rk642(tfp0, _rootnode);
    
    // read the original flags
    uint64_t v_mount = rk642(tfp0, rootfs_vnode + KSTRUCT_OFFSET_VNODE_V_UN);
    uint32_t v_flag = rk32_via_tfp02(tfp0, v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1);
    
    // unset rootfs flag
    wk322(tfp0, v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1, v_flag & ~(MNT_ROOTFS >> 8));
    
    // remount
    char *nmz = strdup("/dev/disk0s1s1");
    kern_return_t rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
    
    // set original flags back
    v_mount = rk642(tfp0, rootfs_vnode + KSTRUCT_OFFSET_VNODE_V_UN);
    wk322(tfp0, v_mount + KSTRUCT_OFFSET_MOUNT_MNT_FLAG + 1, v_flag);
    
    return rv;
}
