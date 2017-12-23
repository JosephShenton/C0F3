
//
//  amfi_codesign.h
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef amfi_codesign_h
#define amfi_codesign_h


#define CSMAGIC_REQUIREMENTS        0xfade0c01
#define CSMAGIC_CODEDIRECTORY       0xfade0c02


typedef struct __BlobIndex {
    uint32_t type;                                  /* type of entry */
    uint32_t offset;                                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                                 /* magic number */
    uint32_t length;                                /* total length of SuperBlob */
    uint32_t count;                                 /* number of index entries following */
    CS_BlobIndex index[];                   /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

uint8_t *load_code_signatures(const char *);
uint8_t *amfi_grab_hashes(const char *);

#endif /* amfi_codesign_h */
