/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle *_JUMP_LABEL self-modifying code.
 *    Hook 'arch_jump_label_transform' function.
 *
 * Notes:
 *  - Linux kernel is heavily consuming *_JUMP_LABEL (if enabled). Most of the
 *    Linux distributions provide kernel with these options compiled. It makes
 *    Linux kernel being self-modifying code. It is very troublesome for this
 *    project. We are relying on comparing hashes from the specific memory
 *    regions and by design self-modifications break this functionality.
 *  - We are hooking into low-level *_JUMP_LABEL functions to be able to
 *    monitor whenever new modification is on the way.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 28.I.2019
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_H
#define P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_H

#include "../../../exploit_detection/syscalls/p_install.h"

extern p_lkrg_counter_lock p_jl_lock;

GENERATE_INSTALL_FUNC_PROTO(arch_jump_label_transform)

#endif
