//
//  amfi_codesign.m
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#include <mach-o/fat.h>
#include "amfi_codesign.h"
#include <mach-o/loader.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>

uint8_t *load_code_signature(FILE *binary, size_t slice_offset)
{
    bool signature_found = false;
    uint8_t *result = 0;
    struct load_command lc;
    do {
        fread(&lc, sizeof(lc), 1, binary);
        if (lc.cmd == LC_CODE_SIGNATURE) {
            
            printf("[INFO]: found code signature!\n");
            
            uint32_t off_cs;
            uint32_t size_cs;
            fread(&off_cs, sizeof(uint32_t), 1, binary);
            fread(&size_cs, sizeof(uint32_t), 1, binary);
            
            signature_found = true;
            uint8_t *cd = malloc(size_cs);
            fseek(binary, off_cs, SEEK_SET);
            fread(cd, size_cs, 1, binary);
            result = cd;
            
            break;
            
//            struct { uint32_t offset; uint32_t size; } sig;
//            if(fread(&sig, sizeof(sig), 1, binary) != 1) goto out;
//            if(fseek(binary, slice_offset+sig.offset, SEEK_SET) == -1) goto out;
//            size_t length = sig.size;
//            uint8_t *data = malloc(length);
//            if(!(length && data)) goto out;
//            if(fread(data, length, 1, binary) != 1) goto out;

//            result = lc_code_sig(data, length);
//            free(data);
//            break;
        }

        fseek(binary, lc.cmdsize-sizeof(lc), SEEK_CUR);
    } while(lc.cmd || lc.cmdsize); /* count lc */
out:
    if (!signature_found) {
        printf("[ERROR]: No LC_CODE_SIGNATURE segment found\n");
        result = 0;
    }
    return result;
}

uint8_t *load_code_signatures(const char *path) {
    
    uint8_t *result = 0;
    FILE *binary = fopen(path, "r");

    
    struct mach_header header;
    fread(&header, sizeof(header), 1, binary);
    if ((header.magic == MH_MAGIC) || (header.magic == MH_MAGIC_64)) {
        
        // iOS 11 doesn't even support 32-bit
        if (header.magic != MH_MAGIC_64) {
            printf("[WARNING]: skipping a non-64bit header in: %s\n", path);
            goto cleanup;
        }
        
        fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
        printf("[INFO]: loading code signature for non-FAT binary: %s\n", path);
        result = load_code_signature(binary, 0 /*non fat*/);
        if(result == 0) {
            printf("[ERROR]: no code signature found!\n");
            goto cleanup;
        }

    } else {
        struct fat_header fat;
        fseek(binary, 0L, SEEK_SET);
        fread(&fat, sizeof(fat), 1, binary);
        
        if(ntohl(fat.magic) != FAT_MAGIC){
            printf("[ERROR]: no FAT_MAGIC found..\n");
            goto cleanup;
        }
        
        uint32_t slice, slices = ntohl(fat.nfat_arch);
        struct fat_arch *archs = calloc(slices, sizeof(struct fat_arch));
        fread(archs, sizeof(struct fat_arch), slices, binary);
        
        for (slice = 0; slice < slices; slice++) {
            
            uint32_t slice_offset = ntohl(archs[slice].offset);
            fseek(binary, slice_offset, SEEK_SET);
            fread(&header, sizeof(header), 1, binary);
            
            // iOS 11 doesn't even support 32-bit
            if (header.magic != MH_MAGIC_64) {
                printf("[WARNING]: skipping a non-64bit header in: %s\n", path);
                continue;
            }
                
            fseek(binary, sizeof(struct mach_header_64) - sizeof(struct mach_header), SEEK_CUR);
            
            printf("[INFO]: loading code signature for FAT binary: %s\n", path);
            result = load_code_signature(binary, slice_offset);
            if(result == 0)
                printf("[ERROR]: no code signature found!\n");

        }
    }
    
cleanup:
    fclose(binary);
    return result;
}


/*
 *  Purpose: since iOS 11 uses SHA256 and libjb doesn't support it yet
 *  I had to re-write this :/
 *  references: codesign.c (Apple)
 */
uint8_t *calculate_sha256(uint8_t* cs_CodeDirectory) {
    
    // from xerub's and INF3995
#define SWAP_UINT32(val)   \
val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF); \
(val << 16) | (val >> 16);
    
    uint32_t* cs_CodeDirectory_count = (uint32_t*)cs_CodeDirectory;
    
    uint32_t realsize = 0;
    int count = 0;
    for (count = 0; count < 10; count++) {
        
        uint32_t magic = SWAP_UINT32(cs_CodeDirectory_count[count]);
        
        switch(magic) {
            case CSMAGIC_REQUIREMENTS:
                break;
            case CSMAGIC_CODEDIRECTORY:
                
                realsize = SWAP_UINT32(cs_CodeDirectory_count[count + 1]);
                cs_CodeDirectory += 4 * count;
                
                break;
        }
    }
    printf("[INFO]: realsize: %08x\n", realsize);
    
    uint8_t *result = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(cs_CodeDirectory, realsize, result);
    return result;
}


/*
 *  Purpose: grabs hashes for a dir (similar to xerub's but SHA256)
 *  parts were taken from triple_fetch and MachOSign
 */
uint8_t *amfi_grab_hashes(const char *path) {
    
    uint8_t *result = load_code_signatures(path);
    
    printf("[INFO]: code signature for %s: %s\n", path, result);
    
    // calculate the hash
    uint8_t *amfi_hash = calculate_sha256(result);
    printf("[INFO]: amfi_hash for %s: %s\n", path, amfi_hash);
    
    return amfi_hash;
}


