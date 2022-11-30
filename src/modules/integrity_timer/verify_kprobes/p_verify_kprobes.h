/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Integrity verification kprobe verification submodule
 *
 * Notes:
 *  - Verify if kprobes are enabled and correctly run
 *
 * Timeline:
 *  - Created: 2.XII.2022
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_INTEGRITY_VERIFY_KPROBES_H
#define P_LKRG_INTEGRITY_VERIFY_KPROBES_H

int lkrg_verify_kprobes(void);

int p_install_lkrg_dummy_hook(int p_isra);
void p_uninstall_lkrg_dummy_hook(void);

#endif
