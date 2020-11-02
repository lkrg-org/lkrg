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

#if defined(CONFIG_FUNCTION_TRACER)

#ifndef P_LKRG_FTRACE_ENABLE_SYSCTL_H
#define P_LKRG_FTRACE_ENABLE_SYSCTL_H

/* per-instance private data */
struct p_ftrace_enable_sysctl_data {
    ktime_t entry_stamp;
};


int p_ftrace_enable_sysctl_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_ftrace_enable_sysctl_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_ftrace_enable_sysctl_hook(void);
void p_uninstall_ftrace_enable_sysctl_hook(void);

#endif

#endif
