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

#include "../../../exploit_detection/syscalls/p_install.h"

extern p_lkrg_counter_lock p_static_call_spinlock;

GENERATE_INSTALL_FUNC_PROTO(arch_static_call_transform)

#endif

#endif
