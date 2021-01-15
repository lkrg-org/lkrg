/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle dynamic FTRACE self-modifying code.
 *    Hook 'ftrace_modify_all_code' function.
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

#if defined(CONFIG_DYNAMIC_FTRACE)

#ifndef P_LKRG_FTRACE_MODIFY_ALL_CODE_H
#define P_LKRG_FTRACE_MODIFY_ALL_CODE_H

/* per-instance private data */
struct p_ftrace_modify_all_code_data {
    ktime_t entry_stamp;
};

#define p_for_ftrace_rec_iter(iter)                    \
   for (iter = P_SYM(p_ftrace_rec_iter_start)();       \
        iter;                                          \
        iter = P_SYM(p_ftrace_rec_iter_next)(iter))


int p_ftrace_modify_all_code_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_ftrace_modify_all_code_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_ftrace_modify_all_code_hook(void);
void p_uninstall_ftrace_modify_all_code_hook(void);

#endif

#endif
