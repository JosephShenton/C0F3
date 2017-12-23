#ifndef symbols_h
#define symbols_h

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include "symbols.h"
#include "kmem.h"
#include "kutils.h"

enum kstruct_offset {
  /* struct task */
  KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
  KSTRUCT_OFFSET_TASK_REF_COUNT,
  KSTRUCT_OFFSET_TASK_ACTIVE,
  KSTRUCT_OFFSET_TASK_VM_MAP,
  KSTRUCT_OFFSET_TASK_NEXT,
  KSTRUCT_OFFSET_TASK_PREV,
  KSTRUCT_OFFSET_TASK_ITK_SPACE,
  KSTRUCT_OFFSET_TASK_BSD_INFO,
  
  /* struct ipc_port */
  KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
  KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
  KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
  KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
  KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
  KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
  KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
  KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
  
  /* struct proc */
  KSTRUCT_OFFSET_PROC_PID,
  KSTRUCT_OFFSET_PROC_COMM,
  
  /* struct ipc_space */
  KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE,
  
  /* struct thread */
  KSTRUCT_OFFSET_THREAD_BOUND_PROCESSOR,
  KSTRUCT_OFFSET_THREAD_LAST_PROCESSOR,
  KSTRUCT_OFFSET_THREAD_CHOSEN_PROCESSOR,
  KSTRUCT_OFFSET_THREAD_CONTEXT_DATA,     // thread.machine.contextData
  KSTRUCT_OFFSET_THREAD_UPCB,             // thread.machine.upcb
  KSTRUCT_OFFSET_THREAD_UNEON,            // thread.machine.uNeon
  KSTRUCT_OFFSET_THREAD_KSTACKPTR,
  
  /* struct processor */
  KSTRUCT_OFFSET_PROCESSOR_CPU_ID,
  
  /* struct cpu_data */
  KSTRUCT_OFFSET_CPU_DATA_EXCEPSTACKPTR,  // despite the name this actually points to the top of the stack, not the bottom
  KSTRUCT_OFFSET_CPU_DATA_CPU_PROCESSOR,
};



// the

enum ksymbol {
  KSYMBOL_OSARRAY_GET_META_CLASS,
  KSYMBOL_IOUSERCLIENT_GET_META_CLASS,
  KSYMBOL_IOUSERCLIENT_GET_TARGET_AND_TRAP_FOR_INDEX,
  KSYMBOL_CSBLOB_GET_CD_HASH,
  KSYMBOL_KALLOC_EXTERNAL,
  KSYMBOL_KFREE,
  KSYMBOL_RET,
  KSYMBOL_OSSERIALIZER_SERIALIZE,
  KSYMBOL_KPRINTF,
  KSYMBOL_UUID_COPY,
  KSYMBOL_CPU_DATA_ENTRIES,
  KSYMBOL_VALID_LINK_REGISTER,
  KSYMBOL_X21_JOP_GADGET,
  KSYMBOL_EXCEPTION_RETURN,
  KSYMBOL_THREAD_EXCEPTION_RETURN,
  KSYMBOL_SET_MDSCR_EL1_GADGET,
  KSYMBOL_WRITE_SYSCALL_ENTRYPOINT,
  KSYMBOL_EL1_HW_BP_INFINITE_LOOP,
  KSYMBOL_SLEH_SYNC_EPILOG
};

int koffset(enum kstruct_offset);

uint64_t ksym(enum ksymbol);

kern_return_t offsets_init(void);
void symbols_init(void);
int probably_have_correct_symbols(void);


#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */


#endif
