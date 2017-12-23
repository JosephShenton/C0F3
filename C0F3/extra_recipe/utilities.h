//
//  utilities.h
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef utilities_h
#define utilities_h


kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);


// kernel read
size_t kread(uint64_t where, void *p, size_t size);
uint64_t kread_uint64(uint64_t where);
uint32_t kread_uint32(uint64_t where);

// kernel write
size_t kwrite(uint64_t where, const void *p, size_t size);
size_t kwrite_uint64(uint64_t where, uint64_t value);
size_t kwrite_uint32(uint64_t where, uint32_t value);

// kernel other
uint64_t kalloc_uint64(vm_size_t size);
#endif /* utilities_h */
