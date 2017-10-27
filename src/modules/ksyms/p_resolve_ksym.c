/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Resolve kernel symbols
 *
 * Notes:
 *  - We try to 'resolve' old-school Linux kernel function for
 *    resolving symbols on run-time
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

unsigned long (*p_kallsyms_lookup_name)(const char *name) = 0x0;


static int p_lookup_syms_hack(void *unused, const char *name,
                              struct module *mod, unsigned long addr) {

   if (strcmp("kallsyms_lookup_name", name) == 0x0) {
      return addr;
   }

   return 0x0;
}

long get_kallsyms_address(void) {

   int p_tmp = 0x0;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <get_kallsyms_address>\n");

   if ( (p_tmp = kallsyms_on_each_symbol(p_lookup_syms_hack,NULL)) == 0x0) {
// DEBUG
      p_debug_log(P_LKRG_DBG,
             "kallsyms_on_each_symbol error :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto get_kallsyms_address_out;
   }

// DEBUG
      p_debug_log(P_LKRG_DBG,
             "kallsyms_on_each_symbol() returned => 0x%x\n",p_tmp);

#ifdef CONFIG_X86_64
   p_kallsyms_lookup_name = (unsigned long (*)(const char*)) (0xFFFFFFFF00000000 | p_tmp);
#else
   p_kallsyms_lookup_name = (unsigned long (*)(const char*)) (p_tmp);
#endif

get_kallsyms_address_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <get_kallsyms_address> (p_ret => %d)\n",p_ret);

   return P_LKRG_SUCCESS;
}
