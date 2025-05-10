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

#include "../../../../exploit_detection/syscalls/p_install.h"

GENERATE_INSTALL_FUNC_PROTO(switch_idt)

#endif

#endif

#endif
