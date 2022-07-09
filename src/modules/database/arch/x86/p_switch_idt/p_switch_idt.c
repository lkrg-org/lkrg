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

char p_switch_idt_kretprobe_state = 0;

static struct kretprobe p_switch_idt_kretprobe = {
    .kp.symbol_name = "switch_idt",
    .handler = p_switch_idt_ret,
    .entry_handler = p_switch_idt_entry,
    .data_size = sizeof(struct p_switch_idt_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};


int p_switch_idt_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   spin_lock(&p_db_lock);

   /* A dump_stack() here will give a stack backtrace */
   return 0;
}


int p_switch_idt_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

/*
   on_each_cpu(p_dump_CPU_metadata,p_tmp_cpus,true);
   p_tmp_hash = hash_from_CPU_data(p_tmp_cpus);
*/
   smp_call_function_single(smp_processor_id(),p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
   p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);

   spin_unlock(&p_db_lock);

   return 0;
}


int p_install_switch_idt_hook(void) {

   int p_tmp;

   if ( (p_tmp = register_kretprobe(&p_switch_idt_kretprobe)) != 0) {
      p_print_log(P_LOG_ISSUE, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  p_tmp);
      return P_LKRG_GENERAL_ERROR;
   }
   p_print_log(P_LOG_WATCH, "Planted [kretprobe] <%s> at: 0x%lx",
               p_switch_idt_kretprobe.kp.symbol_name,
               (unsigned long)p_switch_idt_kretprobe.kp.addr);
   p_switch_idt_kretprobe_state = 1;

   return P_LKRG_SUCCESS;
}


void p_uninstall_switch_idt_hook(void) {

   if (!p_switch_idt_kretprobe_state) {
      p_print_log(P_LOG_WATCH, "[kretprobe] <%s> at 0x%lx is NOT installed",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  (unsigned long)p_switch_idt_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_switch_idt_kretprobe);
      p_print_log(P_LOG_WATCH, "Removing [kretprobe] <%s> at 0x%lx nmissed[%d]",
                  p_switch_idt_kretprobe.kp.symbol_name,
                  (unsigned long)p_switch_idt_kretprobe.kp.addr,
                  p_switch_idt_kretprobe.nmissed);
      p_switch_idt_kretprobe_state = 0;
   }
}

#endif
