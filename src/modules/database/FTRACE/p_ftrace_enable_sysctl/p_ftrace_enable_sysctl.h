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

#include "../../../exploit_detection/syscalls/p_install.h"

GENERATE_INSTALL_FUNC_PROTO(ftrace_enable_sysctl)

#endif

#endif
