/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *   => Submodule - X86/AMD64 specific structures
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 28.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_X86_METADATA_H
#define P_LKRG_X86_METADATA_H

/*
 * Submodule for MSRs
 */
#include "MSR.h"

/*
 * IDT descriptor
 */
#ifdef CONFIG_X86_64
typedef struct p_idt_descriptor {

   unsigned short off_low;
   unsigned short sel;
   unsigned char none, flags;
   unsigned short off_midl;
   unsigned int off_high;
   unsigned int padding;

} p_idt_descriptor;
#else
typedef struct p_idt_descriptor {

   unsigned short off_low;
   unsigned short sel;
   unsigned char none, flags;
   unsigned short off_high;

} p_idt_descriptor;
#endif

#define P_X86_MAX_IDT 256

/*
 * Each CPU in the system independently dump own critical data and save it using
 * following structure - it includes:
 *  - IDT base
 *  - IDT size
 *  - hash from the entire IDT
 *  - MSR (Model Specific Registers)
 */
typedef struct p_CPU_metadata_hash_mem {

   /*
    * Some information about CPU to support hot-plug[in/out]
    */
   int p_cpu_id;
   char p_cpu_online; // 1 - online, 0 - offline

   /*
    * IDT information
    */
   unsigned long p_base;         // IDT base from IDTR
   uint16_t   p_size;            // LKRG's view of IDT size (0x100 or 0)
   uint64_t   p_hash;            // hash from entire IDT (of p_size elements)

   /*
    * Now MSRs...
    */
   char       p_MSR_marker;

   /* x86 critical MSRs */
   u64        p_MSR_IA32_SYSENTER_CS;        // 0x00000174
   u64        p_MSR_IA32_SYSENTER_ESP;       // 0x00000175
   u64        p_MSR_IA32_SYSENTER_EIP;       // 0x00000176

   /* MSR PAT */
//   u64        p_MSR_IA32_CR_PAT;             // 0x00000277

   /* MSR APIC */
   u64        p_MSR_IA32_APICBASE;           // 0x0000001b

   /* MSR EFER - extended feature register */
   u64        p_MSR_EFER;                    // 0xc0000080


   /* AMD64 critical MSRs */

   /* MSR STAR - legacy mode SYSCALL target */
   u64        p_MSR_STAR;                    // 0xc0000081

   /*
    * From: "arch/x86/kernel/cpu/common.c"
    *
    * AMD64 syscalls:
    *     wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
    *
    */
   /* MSR LSTAR - long mode SYSCALL target */
   u64        p_MSR_LSTAR;                   // 0xc0000082

   /* MSR CSTAR - compat mode SYSCALL target */
   u64        p_MSR_CSTAR;                   // 0xc0000083

   /* MSR SYSCALL_MASK - EFLAGS mask for syscall */
   u64        p_MSR_SYSCALL_MASK;            // 0xc0000084

   /* MSR KERNEL_GS_BASE - SwapGS GS shadow */
//   u64        p_MSR_KERNEL_GS_BASE;          // 0xc0000102 <- more research needed,
                                               // saw some user mode code which might
                                               // change that - arch prctl

   /*
    * ... MORE MSRs ... ;)
    */

} p_CPU_metadata_hash_mem;

void p_dump_x86_metadata(void *_p_arg);
//void p_dump_x86_metadata(p_CPU_metadata_hash_mem *p_arg);

#endif
