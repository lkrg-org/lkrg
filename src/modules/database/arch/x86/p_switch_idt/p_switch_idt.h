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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)

#ifdef CONFIG_X86

#ifndef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H
#define P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

/* per-instance private data */
struct p_switch_idt_data {
    ktime_t entry_stamp;
};


int p_switch_idt_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_switch_idt_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_switch_idt_hook(void);
void p_uninstall_switch_idt_hook(void);

#endif

#endif

#endif
