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

//unsigned long (*p_kallsyms_lookup_name)(const char *name) = 0x0;


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

static int p_tmp_kprobe_handler(struct kprobe *p_ri, struct pt_regs *p_regs) {
   return 0x0;
}

#else

static int p_lookup_syms_hack(void *unused, const char *name,
                              struct module *mod, unsigned long addr) {

   if (strcmp("kallsyms_lookup_name", name) == 0x0) {
      P_SYM(p_kallsyms_lookup_name) = (unsigned long (*)(const char*)) (addr);
      return addr;
   }

   return 0x0;
}

#endif

long get_kallsyms_address(void) {

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
   struct kprobe p_kprobe;
#else
   int p_tmp = 0x0;
#endif
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <get_kallsyms_address>\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

   /* "Inspiried" idea from LTTng module */
   memset(&p_kprobe, 0, sizeof(p_kprobe));
   p_kprobe.pre_handler = p_tmp_kprobe_handler;
   p_kprobe.symbol_name = "kallsyms_lookup_name";
   if ( (p_ret = register_kprobe(&p_kprobe)) < 0) {
      p_print_log(P_LKRG_ERR,
             "[get_kallsyms_address] register_kprobe error [%d] :(\n",p_ret);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto get_kallsyms_address_out;
   }
   P_SYM(p_kallsyms_lookup_name) =
         (unsigned long (*)(const char*))((unsigned long)p_kprobe.addr);

#ifdef CONFIG_ARM
#ifdef CONFIG_THUMB2_KERNEL
   if (P_SYM(p_kallsyms_lookup_name))
      P_SYM(p_kallsyms_lookup_name) |= 1; /* set bit 0 in address for thumb mode */
#endif
#endif

   unregister_kprobe(&p_kprobe);

#else

   if ( (p_tmp = kallsyms_on_each_symbol(p_lookup_syms_hack,NULL)) == 0x0) {
// DEBUG
      p_debug_log(P_LKRG_DBG,
             "kallsyms_on_each_symbol error :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto get_kallsyms_address_out;
   }

   p_print_log(P_LKRG_INFO,
          "kallsyms_on_each_symbol() returned => 0x%x [0x%lx]\n",
          p_tmp,
          (unsigned long)P_SYM(p_kallsyms_lookup_name));

#endif

get_kallsyms_address_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <get_kallsyms_address> (p_ret => %d)\n",p_ret);

   return p_ret;
}
