//
//  offsets.h
//  v0rtexNonce
//
//  Created by ninja on 12/12/17.
//  exploit by siguza
//  Copyright Â© 2017 ninja. All rights reserved.
//
#ifndef OFFSETS_H
#define OFFSETS_H
#include "common.h"
#include "sys/utsname.h"
#include "sys/sysctl.h"




void load_offsets(void);




UInt64 OFFSET_ZONE_MAP;
UInt64 OFFSET_KERNEL_MAP;
UInt64 OFFSET_KERNEL_TASK;
UInt64 OFFSET_REALHOST;
UInt64 OFFSET_BZERO;
UInt64 OFFSET_BCOPY;
UInt64 OFFSET_COPYIN;
UInt64 OFFSET_COPYOUT;
UInt64 OFFSET_IPC_PORT_ALLOC_SPECIAL;
UInt64 OFFSET_IPC_KOBJECT_SET;
UInt64 OFFSET_IPC_PORT_MAKE_SEND;
UInt64 OFFSET_IOSURFACEROOTUSERCLIENT_VTAB;
UInt64 OFFSET_ROP_ADD_X0_X0_0x10;


/**--READ BEFORE YOU ADD OFFSETS--**/
//certain models have the same kernelcache. For example, iPhone6,1 and iPhone6,2 (iPhone 5s GSM and global)
//they both have the same ipsw and same kernelcache. Such models should be combined with an OR logic
//check how iPhone 7 and 5s models are combined
//This file has conditions for all devices that have 10.3 or above, including 32 bit ones
//but I haven't combined all devices like I mentioned above. If you're adding offsets for such a device, check the BuildManifest or the sha1 hash of ipsw files, and combine such devices with an OR logic.
//Thanks to everyone who worked hard for this

void load_offsets(void)
{
    struct utsname sysinfo;
    uname(&sysinfo);
    const char *kern_version = sysinfo.version;
    
    //read device id
    int d_prop[2] = {CTL_HW, HW_MACHINE};
    char device[20];
    size_t d_prop_len = sizeof(device);
    //sysctl(d_prop, 2, NULL, &d_prop_len, NULL, 0);
    sysctl(d_prop, 2, device, &d_prop_len, NULL, 0);
    
    int version_prop[2] = {CTL_KERN, KERN_OSVERSION};
    char version[20];
    size_t version_prop_len = sizeof(version);
    //sysctl(version_prop, 2, NULL, &version_prop_len, NULL, 0);
    sysctl(version_prop, 2, version, &version_prop_len, NULL, 0);
    
    //exit(1);
    
    //iPad 4 (WiFi)
    if(!strcmp(device, "iPad3,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad 4 (GSM)
    if(!strcmp(device, "iPad3,5"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad 4 (Global)
    if(!strcmp(device, "iPad3,6"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Air (WiFi)
    if(!strcmp(device, "iPad4,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Air (Cellular)
    if(!strcmp(device, "iPad4,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Air (China)
    if(!strcmp(device, "iPad4,3"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 2 (WiFi)
    if(!strcmp(device, "iPad4,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_COPYIN                               = 0xfffffff007181218;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a8048;
            OFFSET_REALHOST                             = 0xfffffff00752eba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad1d4;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064fd174;
            OFFSET_COPYOUT                              = 0xfffffff00718140c;
            OFFSET_ZONE_MAP                             = 0xfffffff00754c478;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099f7c;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006f2e338;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a8050;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099aa0;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        //10.2.1
        if(!strcmp(version, "14D27"))
        {
            OFFSET_ZONE_MAP                             =  0xfffffff00755a360;
            OFFSET_KERNEL_MAP                           =  0xfffffff0075b6058;
            OFFSET_KERNEL_TASK                          =  0xfffffff0075b6050;
            OFFSET_REALHOST                             =  0xfffffff00753ca98;
            OFFSET_BZERO                                =  0xfffffff007082140;
            OFFSET_BCOPY                                =  0xfffffff007081f80;
            OFFSET_COPYIN                               =  0xfffffff0071835dc;
            OFFSET_COPYOUT                              =  0xfffffff0071837e4;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               =  0xfffffff00709a060;
            OFFSET_IPC_KOBJECT_SET                      =  0xfffffff0070ad700;
            OFFSET_IPC_PORT_MAKE_SEND                   =  0xfffffff007099ba4;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         =  0xfffffff006f336a0;
            OFFSET_ROP_ADD_X0_X0_0x10                   =  0xfffffff00650dfb0;
        }
    }
    
    //iPad Mini 2 (Cellular)
    if(!strcmp(device, "iPad4,5"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff00754c478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a8050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a8048;
            OFFSET_REALHOST                             = 0xfffffff00752eba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff007180e98;
            OFFSET_COPYOUT                              = 0xfffffff00718108c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099f14;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad1ec;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099a38;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006f2e338;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064fe174;
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 2 (China)
    if(!strcmp(device, "iPad4,6"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 3 (WiFi)
    if(!strcmp(device, "iPad4,7"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 3 (Cellular)
    if(!strcmp(device, "iPad4,8"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 3 (China)
    if(!strcmp(device, "iPad4,9"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 4 (WiFi)
    if(!strcmp(device, "iPad5,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Mini 4 (Cellular)
    if(!strcmp(device, "iPad5,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F91"))
        {
            LOG("10.3.2 - 14F91 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Air 2 (WiFi)
    if(!strcmp(device, "iPad5,3"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Air 2 (Cellular)
    if(!strcmp(device, "iPad5,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad 5 (WiFi)
    if(!strcmp(device, "iPad6,11"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F90"))
        {
            LOG("10.3.2 - 14F90 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007548478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a4048;
            OFFSET_REALHOST                             = 0xfffffff00752aba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff007180720;
            OFFSET_COPYOUT                              = 0xfffffff007180914;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099efc;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad154;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099a20;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e65CB8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006429174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad 5 (Cellular)
    if(!strcmp(device, "iPad6,12"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F90"))
        {
            LOG("10.3.2 - 14F90 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 9.7-inch (WiFi)
    if(!strcmp(device, "iPad6,3"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 9.7-inch (Cellular)
    if(!strcmp(device, "iPad6,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1 - not tested
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 12.9-inch (WiFi)
    if(!strcmp(device, "iPad6,7"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 12.9-inch (Cellular)
    if(!strcmp(device, "iPad6,8"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 2 (12.9-inch, WiFi)
    if(!strcmp(device, "iPad7,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F8089"))
        {
            LOG("10.3.2 - 14F8089 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro 2 (12.9-inch, Cellular)
    if(!strcmp(device, "iPad7,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F8089"))
        {
            LOG("10.3.2 - 14F8089 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro (10.5-inch, WiFi)
    if(!strcmp(device, "iPad7,3"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F8089"))
        {
            LOG("10.3.2 - 14F8089 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPad Pro (10.5-inch, Cellular)
    if(!strcmp(device, "iPad7,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F8089"))
        {
            LOG("10.3.2 - 14F8089 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 5 (GSM)
    if(!strcmp(device, "iPhone5,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 5 (Global)
    if(!strcmp(device, "iPhone5,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 5c (GSM)
    if(!strcmp(device, "iPhone5,3"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 5c (Global)
    if(!strcmp(device, "iPhone5,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    
    //iPhone 5s
    if(!strcmp(device, "iPhone6,2") || !strcmp(device, "iPhone6,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff00754c478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a8050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a8048;
            OFFSET_REALHOST                             = 0xfffffff00752eba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff007180e98;
            OFFSET_COPYOUT                              = 0xfffffff00718108c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099f14;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad1ec;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099a38;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006f25538;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006522174;
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff00754c478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a8050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a8048;
            OFFSET_REALHOST                             = 0xfffffff00752eba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff0071811ec;
            OFFSET_COPYOUT                              = 0xfffffff0071813e0;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099f14;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad1ec;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099a38;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006f25538;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006526174;
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff00754c478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a8050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a8048;
            OFFSET_REALHOST                             = 0xfffffff00752eba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff007181218;
            OFFSET_COPYOUT                              = 0xfffffff00718140c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099f7c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad1d4;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099aa0;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006f25538;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006525174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 6+
    if(!strcmp(device, "iPhone7,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 6
    if(!strcmp(device, "iPhone7,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xFFFFFFF007558478;
            OFFSET_KERNEL_MAP                           = 0xFFFFFFF0075B4050;
            OFFSET_KERNEL_TASK                          = 0xFFFFFFF0075B4048;
            OFFSET_REALHOST                             = 0xFFFFFFF00753ABA0;
            OFFSET_BZERO                                = 0xFFFFFFF00708DF80;
            OFFSET_BCOPY                                = 0xFFFFFFF00708DDC0;
            OFFSET_COPYIN                               = 0xFFFFFFF00718D028; //
            OFFSET_COPYOUT                              = 0xFFFFFFF00718D21C;//
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xFFFFFFF0070A60B4;//
            OFFSET_IPC_KOBJECT_SET                      = 0xFFFFFFF0070B938C;//
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xFFFFFFF0070A5BD8;//
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xFFFFFFF006EEE1B8;//
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xFFFFFFF006D91158;//
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d37c;
            OFFSET_COPYOUT                              = 0xfffffff00718d570;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a60b4;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b938c;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5bd8;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            //OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b2174;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006642c90;
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eed1b8; //mdk250
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 6s
    if(!strcmp(device, "iPhone8,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007548478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a4048;
            OFFSET_REALHOST                             = 0xfffffff00752aba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff0071803a0;
            OFFSET_COPYOUT                              = 0xfffffff007180594;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099e94;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad16c;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070999b8;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e7c9f8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006462174;
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007548478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a4048;
            OFFSET_REALHOST                             = 0xfffffff00752aba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff0071806f4;
            OFFSET_COPYOUT                              = 0xfffffff0071808e8;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099e94;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad16c;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070999b8;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e7c9f8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b1398;
        }
        
        //10.3.1 - not tested
        //if doesn't work - find bottom two
        if(!strcmp(version, "14E304"))
        {
            //these are the same as 6s plus, except for the bottom two.
            OFFSET_ZONE_MAP                             = 0xFFFFFFF007548478;
            OFFSET_KERNEL_MAP                           = 0xFFFFFFF0075A4050;
            OFFSET_KERNEL_TASK                          = 0xFFFFFFF0075A4048;
            OFFSET_REALHOST                             = 0xFFFFFFF00752ABA0;
            OFFSET_BZERO                                = 0xFFFFFFF007081F80;
            OFFSET_BCOPY                                = 0xFFFFFFF007081DC0;
            OFFSET_COPYIN                               = 0xFFFFFFF007180720;
            OFFSET_COPYOUT                              = 0xFFFFFFF007180914;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xFFFFFFF007099EFC;
            OFFSET_IPC_KOBJECT_SET                      = 0xFFFFFFF0070AD154;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xFFFFFFF007099A20;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e7c9f8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006b926b4;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 6s+
    if(!strcmp(device, "iPhone8,2"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1 - not tested
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xFFFFFFF007548478;
            OFFSET_KERNEL_MAP                           = 0xFFFFFFF0075A4050;
            OFFSET_KERNEL_TASK                          = 0xFFFFFFF0075A4048;
            OFFSET_REALHOST                             = 0xFFFFFFF00752ABA0;
            OFFSET_BZERO                                = 0xFFFFFFF007081F80;
            OFFSET_BCOPY                                = 0xFFFFFFF007081DC0;
            OFFSET_COPYIN                               = 0xFFFFFFF007180720;
            OFFSET_COPYOUT                              = 0xFFFFFFF007180914;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xFFFFFFF007099EFC;
            OFFSET_IPC_KOBJECT_SET                      = 0xFFFFFFF0070AD154;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xFFFFFFF007099A20;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xFFFFFFF006E7C9F8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006465174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone SE
    if(!strcmp(device, "iPhone8,4"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007548478;
            OFFSET_KERNEL_MAP                           = 0xfffffff007081dc0;
            OFFSET_KERNEL_TASK                          = 0xfffffff0071806f4;
            OFFSET_REALHOST                             = 0xfffffff00752aba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff0071808e8;
            OFFSET_COPYIN                               = 0xfffffff0075a4050;
            OFFSET_COPYOUT                              = 0xfffffff0075a4048;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099e94;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad16c;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070999b8;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e849f8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006482174;
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007548478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075a4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075a4048;
            OFFSET_REALHOST                             = 0xfffffff00752aba0;
            OFFSET_BZERO                                = 0xfffffff007081f80;
            OFFSET_BCOPY                                = 0xfffffff007081dc0;
            OFFSET_COPYIN                               = 0xfffffff007180720;
            OFFSET_COPYOUT                              = 0xfffffff007180914;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff007099efc;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070ad154;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff007099a20;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e83af8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff006481174;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 7
    if(!strcmp(device, "iPhone9,3") || !strcmp(device, "iPhone9,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c5db4;
            OFFSET_COPYOUT                              = 0xfffffff0071c6094;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070deff4;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22cc;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb18;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            // OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0063c5398;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064fb0a8;
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c6108;
            OFFSET_COPYOUT                              = 0xfffffff0071c63e8;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070deff4;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22cc;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb18;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0065000a8;
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c6134;
            OFFSET_COPYOUT                              = 0xfffffff0071c6414;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070df05c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22b4;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb80;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064ff0a8;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    //iPhone 7 Plus
    if(!strcmp(device, "iPhone9,4") || !strcmp(device, "iPhone9,2"))
    {
        //10.1.1 - not tested
        if(!strcmp(version, "14B150") || !strcmp(version, "14B100"))
        {
            //same as 10.2?
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
        //10.2 - not tested
        if(!strcmp(version, "14C92"))
        {
            //same as 10.1.1?
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c5db4;
            OFFSET_COPYOUT                              = 0xfffffff0071c6094;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070deff4;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22cc;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb18;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            // OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0063c5398;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064fb0a8;
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c6108;
            OFFSET_COPYOUT                              = 0xfffffff0071c63e8;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070deff4;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22cc;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb18;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            // OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0063ca398;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0065000a8;
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007590478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075ec050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075ec048;
            OFFSET_REALHOST                             = 0xfffffff007572ba0;
            OFFSET_BZERO                                = 0xfffffff0070c1f80;
            OFFSET_BCOPY                                = 0xfffffff0070c1dc0;
            OFFSET_COPYIN                               = 0xfffffff0071c6134;
            OFFSET_COPYOUT                              = 0xfffffff0071c6414;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070df05c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070f22b4;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070deb80;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006e49208 + 0x1030;
            // OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0063c9398;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064ff0a8;
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        //10.2, 10.1.1
        if(!strcmp(version, "14B150") || !strcmp(version, "14B100") || !strcmp(version, "14C92"))
        {
            OFFSET_ZONE_MAP                             = 0xfffffff007558478;
            OFFSET_KERNEL_MAP                           = 0xfffffff0075b4050;
            OFFSET_KERNEL_TASK                          = 0xfffffff0075b4048;
            OFFSET_REALHOST                             = 0xfffffff00753aba0;
            OFFSET_BZERO                                = 0xfffffff00708df80;
            OFFSET_BCOPY                                = 0xfffffff00708ddc0;
            OFFSET_COPYIN                               = 0xfffffff00718d3a8;
            OFFSET_COPYOUT                              = 0xfffffff00718d59c;
            OFFSET_IPC_PORT_ALLOC_SPECIAL               = 0xfffffff0070a611c;
            OFFSET_IPC_KOBJECT_SET                      = 0xfffffff0070b9374;
            OFFSET_IPC_PORT_MAKE_SEND                   = 0xfffffff0070a5c40;
            OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         = 0xfffffff006eee1b8;
            OFFSET_ROP_ADD_X0_X0_0x10                   = 0xfffffff0064b5174;
        }
        
    }
    
    //iPod touch 6
    if(!strcmp(device, "iPod7,1"))
    {
        //10.3.3
        if(!strcmp(version, "14G60"))
        {
            LOG("10.3.3 - 14G60 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.2
        if(!strcmp(version, "14F89"))
        {
            LOG("10.3.2 - 14F89 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3.1
        if(!strcmp(version, "14E304"))
        {
            LOG("10.3.1 - 14E304 offsets not found for %s", device);
            exit(1);
        }
        
        //10.3
        if(!strcmp(version, "14E277"))
        {
            LOG("10.3 - 14E277 offsets not found for %s", device);
            exit(1);
        }
        
        
    }
    
    
    LOG("%s", kern_version);
    LOG("loading offsets for %s - %s", device, version);
    LOG("test offset x0x0x10gadget: %llx", OFFSET_ROP_ADD_X0_X0_0x10);
}



#endif
