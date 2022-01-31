/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Tracepoints: hook 'arch_static_call_transform' function.
 *
 * Notes:
 *  - Since kernel 5.10 tracepoints don't use JUMP_LABEL engine for .text
      kernel modifications.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 22.IV.2021
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifdef CONFIG_HAVE_STATIC_CALL

#ifndef P_LKRG_CI_ARCH_STATIC_CALL_TRANSFORM_H
#define P_LKRG_CI_ARCH_STATIC_CALL_TRANSFORM_H

/* per-instance private data */
struct p_arch_static_call_transform_data {
    ktime_t entry_stamp;
};

extern p_lkrg_counter_lock p_static_call_spinlock;

int p_arch_static_call_transform_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_arch_static_call_transform_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_arch_static_call_transform_hook(void);
void p_uninstall_arch_static_call_transform_hook(void);

#endif

#endif
