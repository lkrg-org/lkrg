/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle *_JUMP_LABEL self-modifying code.
 *    Hook 'arch_jump_label_transform_apply' function.
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
 *  - Since kernel 5.3 Linux has support for 'batch mode' *_JUMP_LABEL.
 *    Let's handle that as well.
 *
 *    https://lore.kernel.org/patchwork/patch/1064287/
 *
 * Timeline:
 *  - Created: 31.X.2019
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#if defined(CONFIG_X86)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) || \
   (defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 2))

#ifndef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H
#define P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H

#include <asm/linkage.h> /* for ASM_RET */

/*
 * This can be extended to other LTS or active branches if and when they
 * receive the variable length JUMP_LABEL feature backport, although the
 * addition of ASM_RET is part of the same change set and thus our check
 * for it hopefully makes the specific kernel version checks redundant.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 40)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 133)) || \
    defined(ASM_RET)
 #define P_LKRG_KERNEL_HAS_VAR_LEN_JUMP_LABEL 1
#else
 #define P_LKRG_KERNEL_HAS_VAR_LEN_JUMP_LABEL 0
#endif

#include <asm/text-patching.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
 #if !P_LKRG_KERNEL_HAS_VAR_LEN_JUMP_LABEL
typedef struct _p_text_poke_loc {
    s32 rel_addr; /* addr := _stext + rel_addr */
    s32 rel32;
    u8 opcode;
    const u8 text[POKE_MAX_OPCODE_SIZE];
} p_text_poke_loc;
 #else
typedef struct _p_text_poke_loc {
    /* addr := _stext + rel_addr */
    s32 rel_addr;
    s32 disp;
    u8 len;
    u8 opcode;
    const u8 text[POKE_MAX_OPCODE_SIZE];
    /* see text_poke_bp_batch() */
    u8 old;
} p_text_poke_loc;
 #endif
#else
typedef struct text_poke_loc p_text_poke_loc;
#endif

#define P_TP_VEC_MAX (PAGE_SIZE / sizeof(p_text_poke_loc))

/* per-instance private data */
struct p_arch_jump_label_transform_apply_data {
    ktime_t entry_stamp;
};


int p_arch_jump_label_transform_apply_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);
int p_arch_jump_label_transform_apply_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
int p_install_arch_jump_label_transform_apply_hook(void);
void p_uninstall_arch_jump_label_transform_apply_hook(void);

#endif

#endif

#endif
