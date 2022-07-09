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

   P_SYM_INIT(core_kernel_text, int (*)(unsigned long))

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

   if (p_install_switch_idt_hook()) {
      p_print_log(P_LOG_ISSUE,
             "Can't hook 'switch_idt'. "
             "It's OK, but tracepoints might not be supported correctly "
             "(could lead to false positives from LKRG, depending on the kernel version).");
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
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform'");
      return P_LKRG_GENERAL_ERROR;
   }

#ifdef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H
   /*
    * This is not an arch specific hook, but it's a good place to register it
    */
   if (p_install_arch_jump_label_transform_apply_hook()) {
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform_apply'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_DYNAMIC_FTRACE)
   /*
    * Same for FTRACE
    */
   if (p_install_ftrace_modify_all_code_hook()) {
      p_print_log(P_LOG_FATAL, "Can't hook 'ftrace_modify_all_code'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_FUNCTION_TRACER)
   if (p_install_ftrace_enable_sysctl_hook()) {
      p_print_log(P_LOG_FATAL, "Can't hook 'ftrace_enable_sysctl'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_HAVE_STATIC_CALL)
   if (p_install_arch_static_call_transform_hook()) {
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

   return P_LKRG_SUCCESS;

p_sym_error:
   return P_LKRG_GENERAL_ERROR;
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
#if defined(CONFIG_DYNAMIC_FTRACE)
   p_uninstall_ftrace_modify_all_code_hook();
#endif
#if defined(CONFIG_FUNCTION_TRACER)
   p_uninstall_ftrace_enable_sysctl_hook();
#endif
#if defined(CONFIG_HAVE_STATIC_CALL)
   p_uninstall_arch_static_call_transform_hook();
#endif

   return P_LKRG_SUCCESS;
}
