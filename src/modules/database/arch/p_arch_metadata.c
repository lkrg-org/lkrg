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

#include "../../../p_lkrg_main.h"


void p_dump_CPU_metadata(void *_p_arg) {

   p_ed_pcfi_cpu(0);

#ifdef CONFIG_X86

   p_dump_x86_metadata(_p_arg);

#elif defined(CONFIG_ARM64)

   p_dump_arm64_metadata(_p_arg);

#elif defined(CONFIG_ARM)

   p_dump_arm_metadata(_p_arg);

#endif

}

int p_register_arch_metadata(void) {

   P_SYM(p_core_kernel_text) = (int (*)(unsigned long))P_SYM(p_kallsyms_lookup_name)("core_kernel_text");

   if (!P_SYM(p_core_kernel_text)) {
      p_print_log(P_LKRG_ERR,
             "[ED] ERROR: Can't find 'core_kernel_text' function :( Exiting...\n");
      return P_LKRG_GENERAL_ERROR;
   }

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

   if (p_install_switch_idt_hook()) {
      p_print_log(P_LKRG_CRIT,
             "ERROR: Can't hook 'switch_idt' function :( "
             "It's OK, but tracelogs might be not supported - if enabled, it might generate FP! (depends on the kernel version)\n");
      //
      // p_ret = P_LKRG_GENERAL_ERROR;
      // goto error path
      //
      // The reason why we do not stop initialization here (error condition)
      // is because this can only happen in kernel < 3.10 - which is rare and acceptable.
      //
   }

#endif

   /*
    * This is not an arch specific hook, but it's a good place to register it
    */
   if (p_install_arch_jump_label_transform_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't hook arch_jump_label_transform function :(\n");
      return P_LKRG_GENERAL_ERROR;
   }

#ifdef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H
   /*
    * This is not an arch specific hook, but it's a good place to register it
    */
   if (p_install_arch_jump_label_transform_apply_hook()) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't hook arch_jump_label_transform_apply function :(\n");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

   return P_LKRG_SUCCESS;
}


int p_unregister_arch_metadata(void) {

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H
   p_uninstall_switch_idt_hook();
#endif

   /*
    * This is not an arch specific hook, but it's a good place to deregister it
    */
   p_uninstall_arch_jump_label_transform_hook();
#ifdef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H
   p_uninstall_arch_jump_label_transform_apply_hook();
#endif

   return P_LKRG_SUCCESS;
}
