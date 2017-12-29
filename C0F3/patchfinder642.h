#ifndef PATCHFINDER64_H_
#define PATCHFINDER64_H_

#import "common.h"
#import <mach/mach.h>

int init_patchfinder(task_t tfp02, uint64_t base, const char *filename);
void term_kernel2(void);

enum { SearchInCore, SearchInPrelink };

uint64_t find_register_value(uint64_t where, int reg);
uint64_t find_reference2(uint64_t to, int n, int prelink);
uint64_t find_strref2(const char *string, int n, int prelink);
uint64_t find_gPhysBase(void);
uint64_t find_kernel_pmap(void);
uint64_t find_amfiret(void);
uint64_t find_ret_0(void);
uint64_t find_amfi_memcmpstub(void);
uint64_t find_sbops(void);
uint64_t find_lwvm_mapio_patch(void);
uint64_t find_lwvm_mapio_newj(void);

uint64_t find_entry(void);
const unsigned char *find_mh(void);

uint64_t find_cpacr_write(void);
uint64_t find_str(const char *string);
uint64_t find_amfiops(void);
uint64_t find_sysbootnonce(void);
uint64_t find_trustcache2(void);
uint64_t find_amficache2(void);

uint64_t find_allproc2(void);

#endif
