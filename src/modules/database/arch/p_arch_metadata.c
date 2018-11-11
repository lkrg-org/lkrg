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


int p_register_arch_metadata(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_register_arch_metadata>\n");

#ifdef CONFIG_X86
#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

   if (p_install_switch_idt_hook()) {
      p_print_log(P_LKRG_CRIT,
             "ERROR: Can't hook 'switch_idt' function :( "
             "It's OK, but tracelogs won't be supported - if enabled, it will generate FP!\n");
      //
      // p_ret = P_LKRG_GENERAL_ERROR;
      // goto error path
      //
      // The reason why we do not stop initialization here (error condition)
      // is because this can only happen in kernel < 3.10 - which is rare and acceptable.
      //
   }

#endif
#endif

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

#ifdef CONFIG_X86
#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H
   p_uninstall_switch_idt_hook();
#endif
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_register_arch_metadata> (p_ret => %d)\n",p_ret);

   return p_ret;
}
