/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database submodule - middle layer for arch specific code
 *
 * Notes:
 *  - For now, it is only for x86
 *
 * Timeline:
 *  - Created: 26.VIII.2018
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_DATABASE_SUBMODULE_ARCH_H
#define P_LKRG_DATABASE_SUBMODULE_ARCH_H

#include "x86/p_switch_idt/p_switch_idt.h"

int p_register_arch_metadata(void);
int p_unregister_arch_metadata(void);

extern int (*p_core_kernel_text)(unsigned long p_addr);

#endif
