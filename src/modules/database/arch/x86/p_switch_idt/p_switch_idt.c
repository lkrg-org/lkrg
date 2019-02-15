/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Intercept 'switch_idt' function
 *
 * Notes:
 *  - Until kernel 4.14+ Linux kernel is switching IDT
 *    when user enable/disables tracepoints.
 *    If this happens, LKRG needs to rebuild DB with
 *    new CPU metadata.
 *
 * Caveats:
 *  - It is only needed for x86 arch
 *
 * Timeline:
 *  - Created: 26.VIII.2018
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../../p_lkrg_main.h"

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

char p_switch_idt_kretprobe_state = 0x0;

static struct kretprobe p_switch_idt_kretprobe = {
    .kp.symbol_name = "switch_idt",
    .handler = p_switch_idt_ret,
    .entry_handler = p_switch_idt_entry,
    .data_size = sizeof(struct p_switch_idt_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};


int p_switch_idt_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_switch_idt_entry>\n");

   spin_lock(&p_db_lock);

   p_debug_kprobe_log(
          "Leaving function <p_switch_idt_entry>\n");

   /* A dump_stack() here will give a stack backtrace */
   return 0x0;
}


int p_switch_idt_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   p_debug_kprobe_log(
          "Entering function <p_switch_idt_ret>\n");


/*
   on_each_cpu(p_dump_IDT_MSR_CRx,p_tmp_cpus,true);
   p_tmp_hash = hash_from_CPU_data(p_tmp_cpus);
*/
   smp_call_function_single(smp_processor_id(),p_dump_IDT_MSR_CRx,p_db.p_IDT_MSR_CRx_array,true);
   p_db.p_IDT_MSR_CRx_hashes = hash_from_CPU_data(p_db.p_IDT_MSR_CRx_array);

   spin_unlock(&p_db_lock);

   p_debug_kprobe_log(
          "Leaving function <p_switch_idt_ret>\n");
   return 0x0;
}


int p_install_switch_idt_hook(void) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_install_switch_idt_hook>\n");

   if ( (p_ret = register_kretprobe(&p_switch_idt_kretprobe)) < 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]\n",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  p_ret);
      goto p_install_switch_idt_hook_out;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: %p\n",
               p_switch_idt_kretprobe.kp.symbol_name,
               p_switch_idt_kretprobe.kp.addr);
   p_switch_idt_kretprobe_state = 0x1;

//   p_ret = 0x0; <- should be 0x0 anyway...

p_install_switch_idt_hook_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_install_switch_idt_hook> (p_ret => %d)\n",p_ret);

   return p_ret;
}


void p_uninstall_switch_idt_hook(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninstall_switch_idt_hook>\n");

   if (!p_switch_idt_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%p is NOT installed\n",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  p_switch_idt_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_switch_idt_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%p nmissed[%d]\n",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  p_switch_idt_kretprobe.kp.addr,
                  p_switch_idt_kretprobe.nmissed);
      p_switch_idt_kretprobe_state = 0x0;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninstall_switch_idt_hook>\n");
}

#endif
