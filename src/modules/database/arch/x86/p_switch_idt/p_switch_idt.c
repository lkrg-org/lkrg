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
#include "../../../../exploit_detection/syscalls/p_install.h"

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

static int p_switch_idt_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   spin_lock(&p_db_lock);
   read_lock(&p_config_lock);

   /* A dump_stack() here will give a stack backtrace */
   return 0;
}

static int p_switch_idt_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

/*
   on_each_cpu(p_dump_CPU_metadata,p_tmp_cpus,true);
   p_tmp_hash = hash_from_CPU_data(p_tmp_cpus);
*/
   smp_call_function_single(smp_processor_id(),p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
   p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);

   read_unlock(&p_config_lock);
   spin_unlock(&p_db_lock);

   return 0;
}

static struct lkrg_probe p_switch_idt_probe = {
  .type = LKRG_KRETPROBE,
  .krp = {
    .kp.symbol_name = "switch_idt",
    .handler = p_switch_idt_ret,
    .entry_handler = p_switch_idt_entry,
  }
};

GENERATE_INSTALL_FUNC(switch_idt)

#endif
