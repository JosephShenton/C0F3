//
//  amfi.h
//  v0rtex-s
//
//  Created by Ben on 19/12/2017.
//  Copyright © 2017 Sticktron. All rights reserved.
//



void init_amfi(task_t task_for_port0);
void trust_files(const char *path);
void inject_trust2(const char *path);

uint8_t *getCodeDirectory2(const char* name);
uint8_t *getSHA2562(uint8_t* code_dir);
uint32_t swap_uint322(uint32_t val);
