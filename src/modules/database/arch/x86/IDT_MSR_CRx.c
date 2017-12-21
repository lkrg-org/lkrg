/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *   => submodule for dumping IDT
 *
 * Notes:
 *  - IDT can be different per CPU which makes it quite complicated...
 *    we need to run 'dumping' IDT on each CPU to be sure everything
 *    is clear.
 *
 *  - Linux kernel defines different types of CPUs:
 *   => online CPUs
 *   => possible CPUs
 *   => present CPUs
 *   => active CPUs
 *
 *    We are going to run procedure only on 'active CPUs' and different
 *    procedure is checking if number of active CPUs changes over time...
 *
 * Timeline:
 *  - Created: 27.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"


u64 p_read_msr(/*int p_cpu, */u32 p_arg) {

    u32 p_low;
    u32 p_high;
    u64 p_val;
//    int p_err;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_read_msr>\n");

   p_low = p_high = p_val = 0x0;

    __asm__("rdmsr": P_MSR_ASM_READ(p_val,p_low,p_high)
                   : "c"(p_arg)
                   : );

// Sometime may generate OOPS ;/
/*
   if ( (p_err = rdmsr_safe_on_cpu(p_cpu,p_arg,&p_low,&p_high))) {
      p_debug_log(P_LKRG_STRONG_DBG,
             "<p_read_msr> rdmsr_safe_on_cpu() error! - shouldn't happend [err=0x%x]!\n",p_err);
      return 0x0;
   }
   p_val = (u64 )p_high << 32 | p_low;
*/

   p_val = P_MSR_ASM_RET(p_val,p_low,p_high);

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_read_msr[%d]> MSR arg[0x%x] value[%llx]\n",smp_processor_id(),p_arg,p_val);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_read_msr>\n");

    return p_val;
}

/*
 * This function is independetly executed by each active CPU.
 * IDT is individual per logical CPU (same as MSRs, etc).
 */
void p_dump_IDT_MSR_CRx(void *_p_arg) {

   p_IDT_MSR_CRx_hash_mem *p_arg = _p_arg;
/*
 * IDTR register
 */
#ifdef CONFIG_X86_64
   unsigned char p_idtr[0xA];
#else
   unsigned char p_idtr[0x6];
#endif

   int p_curr_cpu = 0xFFFFFFFF;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_dump_IDT_MSR_CRx>\n");

   /*
    * Get ID and lock - no preemtion.
    */
//   p_curr_cpu = get_cpu();
   p_curr_cpu = smp_processor_id();

   /*
    * To avoid multpile access to the same page from all CPUs
    * memory will be already zero'd
    */
//   memset(&p_arg[p_curr_cpu],0x0,sizeof(p_IDT_MSR_CRx_hash_mem));

   /*
    * First fill information about current CPU
    */
    p_arg[p_curr_cpu].p_cpu_id = p_curr_cpu;
    p_arg[p_curr_cpu].p_cpu_online = P_CPU_ONLINE;

    /*
     * IDT...
     */
#ifdef CONFIG_X86_64
   __asm__("sidt   %0\n"
           "movq   %3, %%rax\n"
           "movq   %%rax,%1\n"
           "movw   %4,%%ax\n"
           "movw   %%ax,%2\n":"=m"(p_idtr),"=m"(p_arg[p_curr_cpu].p_base),"=m"(p_arg[p_curr_cpu].p_size)
                             :"m"(p_idtr[2]),"m"(p_idtr[0])
                             :"%rax");
#else
   __asm__("sidt   %0\n"
           "movl   %3, %%eax\n"
           "movl   %%eax,%1\n"
           "movw   %4,%%ax\n"
           "movw   %%ax,%2\n":"=m"(p_idtr),"=m"(p_arg[p_curr_cpu].p_base),"=m"(p_arg[p_curr_cpu].p_size)
                             :"m"(p_idtr[2]),"m"(p_idtr[0])
                             :"%eax");
#endif

   p_arg[p_curr_cpu].p_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_curr_cpu].p_base,
                                               (unsigned int)sizeof(p_idt_descriptor) * P_X86_MAX_IDT);

// DEBUG
#ifdef P_LKRG_DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] IDT => base[0x%lx] size[0x%x] hash[0x%llx]\n",
          p_arg[p_curr_cpu].p_cpu_id,p_arg[p_curr_cpu].p_base,p_arg[p_curr_cpu].p_size,p_arg[p_curr_cpu].p_hash);

   do {
      p_idt_descriptor *p_test;

      p_debug_log(P_LKRG_DBG,
             "Reading IDT 1 to verify data:");
      p_test = (p_idt_descriptor *)(p_arg[p_curr_cpu].p_base+(sizeof(p_idt_descriptor)*1));
#ifdef CONFIG_X86_64
      p_debug_log(P_LKRG_DBG,
                "off_low[0x%x]"
                "sel[0x%x]"
                "none[0x%x]"
                "flags[0x%x]"
                "off_midl[0x%x]"
                "off_high[0x%x]"
                "padding[0x%x]\n",
                p_test->off_low,
                p_test->sel,
                p_test->none,
                p_test->flags,
                p_test->off_midl,
                p_test->off_high,
                p_test->padding
                );
#else
      p_debug_log(P_LKRG_DBG,
                "off_low[0x%x]"
                "sel[0x%x]"
                "none[0x%x]"
                "flags[0x%x]"
                "off_high[0x%x]\n",
                p_test->off_low,
                p_test->sel,
                p_test->none,
                p_test->flags,
                p_test->off_high
                );
#endif
   } while(0);

#endif

   /*
    * Now MSRs...
    */

   /* MSR_IA32_SYSENTER_CS */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS,MSR_IA32_SYSENTER_CS);
//   p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS = p_read_msr(p_curr_cpu,MSR_IA32_SYSENTER_CS);

   if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS) {
      p_print_log(P_LKRG_INFO,
             "MSR IA32_SYSENTER_CS offset 0x%x on CPU:[%d] is not set!\n",
             MSR_IA32_SYSENTER_CS,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_CS[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS,&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS);


   /* MSR_IA32_SYSENTER_ESP */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP,MSR_IA32_SYSENTER_ESP);

   if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP) {
      p_print_log(P_LKRG_INFO,
             "MSR IA32_SYSENTER_ESP offset 0x%x on CPU:[%d] is not set!\n",
             MSR_IA32_SYSENTER_ESP,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_ESP[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP,&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP);


   /* MSR_IA32_SYSENTER_EIP */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP,MSR_IA32_SYSENTER_EIP);

   if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP) {
      p_print_log(P_LKRG_INFO,
             "MSR IA32_SYSENTER_EIP offset 0x%x on CPU:[%d] is not set!\n",
             MSR_IA32_SYSENTER_EIP,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_EIP[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP,&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP);


   /* MSR_IA32_CR_PAT */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT,MSR_IA32_CR_PAT);

   if (!p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT) {
      p_print_log(P_LKRG_INFO,
             "MSR IA32_CR_PAT offset 0x%x on CPU:[%d] is not set!\n",
             MSR_IA32_CR_PAT,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_CR_PAT[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT,&p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT);


   /* MSR_IA32_APICBASE */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_APICBASE,MSR_IA32_APICBASE);

   if (!p_arg[p_curr_cpu].p_MSR_IA32_APICBASE) {
      p_print_log(P_LKRG_INFO,
             "MSR IA32_APICBASE offset 0x%x on CPU:[%d] is not set!\n",
             MSR_IA32_APICBASE,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_APICBASE[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_APICBASE,&p_arg[p_curr_cpu].p_MSR_IA32_APICBASE);


   /* MSR_EFER */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_EFER,MSR_EFER);

   if (!p_arg[p_curr_cpu].p_MSR_EFER) {
      p_print_log(P_LKRG_INFO,
             "MSR EFER offset 0x%x on CPU:[%d] is not set!\n",
             MSR_EFER,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_EFER[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_EFER,&p_arg[p_curr_cpu].p_MSR_EFER);


   /* MSR_STAR */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_STAR,MSR_STAR);

   if (!p_arg[p_curr_cpu].p_MSR_STAR) {
      p_print_log(P_LKRG_INFO,
             "MSR STAR offset 0x%x on CPU:[%d] is not set!\n",
             MSR_STAR,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_STAR[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_STAR,&p_arg[p_curr_cpu].p_MSR_STAR);


   /* MSR_LSTAR */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_LSTAR,MSR_LSTAR);

   if (!p_arg[p_curr_cpu].p_MSR_LSTAR) {
      p_print_log(P_LKRG_INFO,
             "MSR LSTAR offset 0x%x on CPU:[%d] is not set!\n",
             MSR_LSTAR,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_LSTAR[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_LSTAR,&p_arg[p_curr_cpu].p_MSR_LSTAR);


   /* MSR_CSTAR */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_CSTAR,MSR_CSTAR);

   if (!p_arg[p_curr_cpu].p_MSR_CSTAR) {
      p_print_log(P_LKRG_INFO,
             "MSR CSTAR offset 0x%x on CPU:[%d] is not set!\n",
             MSR_CSTAR,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_CSTAR[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_CSTAR,&p_arg[p_curr_cpu].p_MSR_CSTAR);


   /* MSR_SYSCALL_MASK */
   // Try reading at least 3 times before give up in case of error...
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK,MSR_SYSCALL_MASK);

   if (!p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK) {
      p_print_log(P_LKRG_INFO,
             "MSR SYSCALL_MASK offset 0x%x on CPU:[%d] is not set!\n",
             MSR_SYSCALL_MASK,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_SYSCALL_MASK[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK,&p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK);


   /* p_MSR_KERNEL_GS_BASE */
   // Try reading at least 3 times before give up in case of error...
/*
   P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE,MSR_KERNEL_GS_BASE);

   if (!p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE) {
      p_print_log(P_LKRG_INFO,
             "MSR KERNEL_GS_BASE offset 0x%x on CPU:[%d] is not set!\n",
             MSR_KERNEL_GS_BASE,p_curr_cpu);
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_KERNEL_GS_BASE[0x%llx] address in db[%p]\n",
          p_curr_cpu,p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE,&p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE);
*/

   /*
    * Now Control Registers
    */

   // TODO...

   /*
    * Unlock preemtion.
    */
//   put_cpu();


// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_dump_IDT_MSR_CRx>\n");

}
