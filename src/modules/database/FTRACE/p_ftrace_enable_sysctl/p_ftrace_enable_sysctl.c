/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle FTRACE functionality for self-modifying code.
 *    Hook 'ftrace_enable_sysctl' function.
 *
 * Notes:
 *  - Linux kernel might be self-modifying using dynamic FTRACE.
 *    Most of the Linux distributions provide kernel with FTRACE enabled.
 *    It can dynamically modify Linux kernel code. It is very troublesome
 *    for this project. We are relying on comparing hashes from the specific
 *    memory regions and by design self-modifications break this functionality.
 *  - We are hooking into low-level FTRACE functions to be able to monitor
 *    whenever new modification is on the way.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 18.IX.2020
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#if defined(P_LKRG_FTRACE_ENABLE_SYSCTL_H)

char p_ftrace_enable_sysctl_kretprobe_state = 0;

static struct kretprobe p_ftrace_enable_sysctl_kretprobe = {
    .kp.symbol_name = "ftrace_enable_sysctl",
    .handler = p_ftrace_enable_sysctl_ret,
    .entry_handler = p_ftrace_enable_sysctl_entry,
    .data_size = sizeof(struct p_ftrace_enable_sysctl_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};

notrace int p_ftrace_enable_sysctl_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_regs_set_arg2(p_regs, 0x0);

   return 0;
}


notrace int p_ftrace_enable_sysctl_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   return 0;
}


int p_install_ftrace_enable_sysctl_hook(void) {

   int p_tmp;

   if ( (p_tmp = register_kretprobe(&p_ftrace_enable_sysctl_kretprobe)) != 0) {
      p_print_log(P_LOG_FATAL, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]",
                  p_ftrace_enable_sysctl_kretprobe.kp.symbol_name,
                  p_tmp);
      return P_LKRG_GENERAL_ERROR;
   }
   p_print_log(P_LOG_WATCH, "Planted [kretprobe] <%s> at: 0x%lx",
               p_ftrace_enable_sysctl_kretprobe.kp.symbol_name,
               (unsigned long)p_ftrace_enable_sysctl_kretprobe.kp.addr);
   p_ftrace_enable_sysctl_kretprobe_state = 1;

   return P_LKRG_SUCCESS;
}


void p_uninstall_ftrace_enable_sysctl_hook(void) {

   if (!p_ftrace_enable_sysctl_kretprobe_state) {
      p_print_log(P_LOG_WATCH, "[kretprobe] <%s> at 0x%lx is NOT installed",
                  p_ftrace_enable_sysctl_kretprobe.kp.symbol_name,
                  (unsigned long)p_ftrace_enable_sysctl_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_ftrace_enable_sysctl_kretprobe);
      p_print_log(P_LOG_WATCH, "Removing [kretprobe] <%s> at 0x%lx nmissed[%d]",
                  p_ftrace_enable_sysctl_kretprobe.kp.symbol_name,
                  (unsigned long)p_ftrace_enable_sysctl_kretprobe.kp.addr,
                  p_ftrace_enable_sysctl_kretprobe.nmissed);
      p_ftrace_enable_sysctl_kretprobe_state = 0;
   }
}

#endif
