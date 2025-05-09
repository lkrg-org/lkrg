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

#include "../../../exploit_detection/syscalls/p_install.h"

static notrace int p_ftrace_enable_sysctl_entry(struct kprobe *p_ri, struct pt_regs *p_regs) {

   p_regs_set_arg2(p_regs, 0x0);

   return 0;
}

static struct lkrg_probe p_ftrace_enable_sysctl_probe = {
  .type = LKRG_KPROBE,
  .krp = {
    .kp.symbol_name = "ftrace_enable_sysctl",
    .kp.pre_handler = p_ftrace_enable_sysctl_entry,
  }
};

GENERATE_INSTALL_FUNC(ftrace_enable_sysctl)

#endif
