//
//  kernel.h
//  v0rtex-s
//
//  Created by Ben on 16/12/2017.
//  Copyright © 2017 Sticktron. All rights reserved.
//

#include <mach/mach.h>
void init_kernel2(task_t task_for_port0);
uint64_t rk642(task_t tfp0, uint64_t kaddr);
uint32_t rk32_via_tfp02(task_t tfp0, uint64_t kaddr);
void wk322(task_t tfp0, uint64_t kaddr, uint32_t val);
void wk642(uint64_t kaddr, uint64_t val);
kern_return_t mach_vm_write(
                            vm_map_t target_task,
                            mach_vm_address_t address,
                            vm_offset_t data,
                            mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_read_overwrite(
                                     vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     mach_vm_address_t data,
                                     mach_vm_size_t *outsize);

size_t kread2(uint64_t where, void *p, size_t size);
size_t kwrite2(uint64_t where, const void *p, size_t size);
size_t kwrite2_uint64(uint64_t where, uint64_t value);
