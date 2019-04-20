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

int (*p_core_kernel_text)(unsigned long p_addr) = 0x0;


void p_dump_CPU_metadata(void *_p_arg) {

#ifdef CONFIG_X86

   p_dump_x86_metadata(_p_arg);

#elif defined(CONFIG_ARM64)

   p_dump_arm64_metadata(_p_arg);

#endif

}

int p_register_arch_metadata(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_register_arch_metadata>\n");

   p_core_kernel_text = (int (*)(unsigned long))p_kallsyms_lookup_name("core_kernel_text");

   if (!p_core_kernel_text) {
      p_print_log(P_LKRG_ERR,
             "[ED] ERROR: Can't find 'core_kernel_text' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_register_arch_metadata_out;
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
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_register_arch_metadata_out;
   }

p_register_arch_metadata_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_register_arch_metadata> (p_ret => %d)\n",p_ret);

   return p_ret;
}


int p_unregister_arch_metadata(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_register_arch_metadata>\n");

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H
   p_uninstall_switch_idt_hook();
#endif

   /*
    * This is not an arch specific hook, but it's a good place to deregister it
    */
   p_uninstall_arch_jump_label_transform_hook();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_register_arch_metadata> (p_ret => %d)\n",p_ret);

   return p_ret;
}
