/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *    => submodule for dumping IDT
 *
 * Notes:
 *  - IDT can be different per CPU which makes it quite complicated...
 *    We need to run 'dumping' function on each CPU individually
 *
 *  - Linux kernel defines different types of CPUs:
 *    => online CPUs
 *    => possible CPUs
 *    => present CPUs
 *    => active CPUs
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

#ifdef CONFIG_X86

u64 p_read_msr(/*int p_cpu, */u32 p_arg) {

    u32 p_low;
    u32 p_high;
    u64 p_val;
//    int p_err;

   p_low = p_high = p_val = 0;

    __asm__("rdmsr": P_MSR_ASM_READ(p_val,p_low,p_high)
                   : "c"(p_arg)
                   : );

// Sometime may generate OOPS ;/
/*
   if ( (p_err = rdmsr_safe_on_cpu(p_cpu,p_arg,&p_low,&p_high))) {
      p_debug_log(P_LOG_FLOOD,
             "<p_read_msr> rdmsr_safe_on_cpu() error! - shouldn't happen [err=0x%x]!",p_err);
      return 0;
   }
   p_val = (u64 )p_high << 32 | p_low;
*/

   p_val = P_MSR_ASM_RET(p_val,p_low,p_high);

// DEBUG
   p_debug_log(P_LOG_DEBUG,
          "<p_read_msr[%d]> MSR arg[0x%x] value[%llx]",smp_processor_id(),p_arg,p_val);

    return p_val;
}

/*
 * This function is independently executed by each active CPU.
 * IDT is individual per logical CPU (same as MSRs, etc).
 */
void p_dump_x86_metadata(void *_p_arg) {

   p_CPU_metadata_hash_mem *p_arg = _p_arg;
/*
 * IDTR register
 */
   struct {
      unsigned char dummy[2]; /* 2+ bytes for limit */
      unsigned long base; /* 4 or 8 bytes */
   } p_idtr;

   int p_curr_cpu = 0xFFFFFFFF;

   /*
    * Get ID and lock - no preemtion.
    */
//   p_curr_cpu = get_cpu();
   p_curr_cpu = smp_processor_id();

   /*
    * To avoid multpile access to the same page from all CPUs
    * memory will be already zero'd
    */
//   memset(&p_arg[p_curr_cpu],0,sizeof(p_CPU_metadata_hash_mem));

   /*
    * First fill information about current CPU
    */
    p_arg[p_curr_cpu].p_cpu_id = p_curr_cpu;
    p_arg[p_curr_cpu].p_cpu_online = P_CPU_ONLINE;

    /*
     * IDT...
     */
   __asm__("sidt %0": "=m" (*((unsigned char *)&p_idtr.base - 2)), "=m" (p_idtr.base));
   p_arg[p_curr_cpu].p_base = p_idtr.base;

   /*
    * On all x86 platforms there's defined maximum P_X86_MAX_IDT vectors.
    * We can hardcode that size here since some 'weird' modules might
    * incorrectly set the limit e.g. to be higher than that.
    */
   p_arg[p_curr_cpu].p_size = P_X86_MAX_IDT;

#if defined(CONFIG_X86_64) && defined(CONFIG_XEN_PVH)
   if (p_arg[p_curr_cpu].p_base >= 0xffff800000000000ULL &&
       p_arg[p_curr_cpu].p_base <= 0xffff87ffffffffffULL) {
      p_arg[p_curr_cpu].p_base = 0;
      p_arg[p_curr_cpu].p_size = 0;
   }
#endif

   p_arg[p_curr_cpu].p_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_curr_cpu].p_base,
                                               sizeof(p_idt_descriptor) * p_arg[p_curr_cpu].p_size);

// DEBUG
#ifdef P_LKRG_DEBUG
   p_debug_log(P_LOG_DEBUG,
          "<p_dump_IDT_MSR> CPU:[%d] IDT => base[0x%lx] size[0x%x] hash[0x%llx]",
          p_arg[p_curr_cpu].p_cpu_id,p_arg[p_curr_cpu].p_base,p_arg[p_curr_cpu].p_size,p_arg[p_curr_cpu].p_hash);

   if (p_arg[p_curr_cpu].p_size)
   do {
      p_idt_descriptor *p_test;

      p_debug_log(P_LOG_DEBUG,
             "Reading IDT 1 to verify data:");
      p_test = (p_idt_descriptor *)(p_arg[p_curr_cpu].p_base+(sizeof(p_idt_descriptor)*1));
#ifdef CONFIG_X86_64
      p_debug_log(P_LOG_DEBUG,
                "off_low[0x%x]"
                "sel[0x%x]"
                "none[0x%x]"
                "flags[0x%x]"
                "off_midl[0x%x]"
                "off_high[0x%x]"
                "padding[0x%x]",
                p_test->off_low,
                p_test->sel,
                p_test->none,
                p_test->flags,
                p_test->off_midl,
                p_test->off_high,
                p_test->padding
                );
#else
      p_debug_log(P_LOG_DEBUG,
                "off_low[0x%x]"
                "sel[0x%x]"
                "none[0x%x]"
                "flags[0x%x]"
                "off_high[0x%x]",
                p_test->off_low,
                p_test->sel,
                p_test->none,
                p_test->flags,
                p_test->off_high
                );
#endif
   } while(0);

#endif


   if (P_CTRL(p_msr_validate)) {

      /*
       * Now MSRs...
       */

      /* MSR_IA32_SYSENTER_CS */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS,MSR_IA32_SYSENTER_CS);
//      p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS = p_read_msr(p_curr_cpu,MSR_IA32_SYSENTER_CS);

      if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS) {
         p_print_log(P_LOG_WATCH,
                "MSR IA32_SYSENTER_CS offset 0x%x on CPU:[%d] is not set!",
                MSR_IA32_SYSENTER_CS,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_CS[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS,(unsigned long)&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_CS);


      /* MSR_IA32_SYSENTER_ESP */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP,MSR_IA32_SYSENTER_ESP);

      if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP) {
         p_print_log(P_LOG_WATCH,
                "MSR IA32_SYSENTER_ESP offset 0x%x on CPU:[%d] is not set!",
                MSR_IA32_SYSENTER_ESP,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_ESP[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP,(unsigned long)&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_ESP);


      /* MSR_IA32_SYSENTER_EIP */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP,MSR_IA32_SYSENTER_EIP);

      if (!p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP) {
         p_print_log(P_LOG_WATCH,
                "MSR IA32_SYSENTER_EIP offset 0x%x on CPU:[%d] is not set!",
                MSR_IA32_SYSENTER_EIP,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_SYSENTER_EIP[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP,(unsigned long)&p_arg[p_curr_cpu].p_MSR_IA32_SYSENTER_EIP);


      /* MSR_IA32_CR_PAT */
      // Try reading at least 3 times before give up in case of error...
      /*
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT,MSR_IA32_CR_PAT);

      if (!p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT) {
         p_print_log(P_LOG_WATCH,
                "MSR IA32_CR_PAT offset 0x%x on CPU:[%d] is not set!",
                MSR_IA32_CR_PAT,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_CR_PAT[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT,(unsigned long)&p_arg[p_curr_cpu].p_MSR_IA32_CR_PAT);
      */

      /* MSR_IA32_APICBASE */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_IA32_APICBASE,MSR_IA32_APICBASE);

      if (!p_arg[p_curr_cpu].p_MSR_IA32_APICBASE) {
         p_print_log(P_LOG_WATCH,
                "MSR IA32_APICBASE offset 0x%x on CPU:[%d] is not set!",
                MSR_IA32_APICBASE,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_IA32_APICBASE[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_IA32_APICBASE,(unsigned long)&p_arg[p_curr_cpu].p_MSR_IA32_APICBASE);


      /* MSR_EFER */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_EFER,MSR_EFER);

      if (!p_arg[p_curr_cpu].p_MSR_EFER) {
         p_print_log(P_LOG_WATCH,
                "MSR EFER offset 0x%x on CPU:[%d] is not set!",
                MSR_EFER,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_EFER[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_EFER,(unsigned long)&p_arg[p_curr_cpu].p_MSR_EFER);


      /* MSR_STAR */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_STAR,MSR_STAR);

      if (!p_arg[p_curr_cpu].p_MSR_STAR) {
         p_print_log(P_LOG_WATCH,
                "MSR STAR offset 0x%x on CPU:[%d] is not set!",
                MSR_STAR,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_STAR[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_STAR,(unsigned long)&p_arg[p_curr_cpu].p_MSR_STAR);


      /* MSR_LSTAR */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_LSTAR,MSR_LSTAR);

      if (!p_arg[p_curr_cpu].p_MSR_LSTAR) {
         p_print_log(P_LOG_WATCH,
                "MSR LSTAR offset 0x%x on CPU:[%d] is not set!",
                MSR_LSTAR,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_LSTAR[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_LSTAR,(unsigned long)&p_arg[p_curr_cpu].p_MSR_LSTAR);


      /* MSR_CSTAR */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_CSTAR,MSR_CSTAR);

      if (!p_arg[p_curr_cpu].p_MSR_CSTAR) {
         p_print_log(P_LOG_WATCH,
                "MSR CSTAR offset 0x%x on CPU:[%d] is not set!",
                MSR_CSTAR,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_CSTAR[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_CSTAR,(unsigned long)&p_arg[p_curr_cpu].p_MSR_CSTAR);


      /* MSR_SYSCALL_MASK */
      // Try reading at least 3 times before give up in case of error...
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK,MSR_SYSCALL_MASK);

      if (!p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK) {
         p_print_log(P_LOG_WATCH,
                "MSR SYSCALL_MASK offset 0x%x on CPU:[%d] is not set!",
                MSR_SYSCALL_MASK,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_SYSCALL_MASK[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK,(unsigned long)&p_arg[p_curr_cpu].p_MSR_SYSCALL_MASK);


      /* p_MSR_KERNEL_GS_BASE */
      // Try reading at least 3 times before give up in case of error...
      /*
      P_MSR_READ_COUNT(3,p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE,MSR_KERNEL_GS_BASE);

      if (!p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE) {
         p_print_log(P_LOG_WATCH,
                "MSR KERNEL_GS_BASE offset 0x%x on CPU:[%d] is not set!",
                MSR_KERNEL_GS_BASE,p_curr_cpu);
      }

      // STRONG_DEBUG
      p_debug_log(P_LOG_FLOOD,
             "<p_dump_IDT_MSR> CPU:[%d] MSR: MSR_KERNEL_GS_BASE[0x%llx] address in db[0x%lx]",
             p_curr_cpu,p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE,(unsigned long)&p_arg[p_curr_cpu].p_MSR_KERNEL_GS_BASE);
      */

   }

   /*
    * Now Control Registers
    */

   // TODO...

   /*
    * Unlock preemtion.
    */
//   put_cpu();

}

#endif
