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


static int p_find_isra_name(void *p_isra_argg, const char *name,
                            struct module *mod, unsigned long addr) {

   struct p_isra_argument *p_isra_arg = (struct p_isra_argument *)p_isra_argg;
   char p_buf[0x100];
   char p_buf2[0x100];

   snprintf(p_buf,0xFF,"%s.isra.",p_isra_arg->p_name);
   p_buf[0xFF] = 0x0;
   snprintf(p_buf2,0xFF,"%s.constprop.",p_isra_arg->p_name);
   p_buf2[0xFF] = 0x0;
   if (strncmp(p_buf, name, strlen(p_buf)) == 0x0) {
      p_print_log(P_LKRG_WARN, "Found ISRA version of function <%s>\n", name);
      if ( (p_isra_arg->p_isra_name = kzalloc(strlen(name)+1, GFP_KERNEL)) == NULL) {
         p_print_log(P_LKRG_ERR, "[p_find_isra_name] kzalloc() failed!\n");
         return 0x0;
      }
      memcpy(p_isra_arg->p_isra_name, name, strlen(name));
      return addr;
   } else if (strncmp(p_buf2, name, strlen(p_buf2)) == 0x0) {
      p_print_log(P_LKRG_WARN, "Found CONSTPROP version of function <%s>\n", name);
      if ( (p_isra_arg->p_isra_name = kzalloc(strlen(name)+1, GFP_KERNEL)) == NULL) {
         p_print_log(P_LKRG_ERR, "[p_find_isra_name] kzalloc() failed!\n");
         return 0x0;
      }
      memcpy(p_isra_arg->p_isra_name, name, strlen(name));
      return addr;
   }

   return 0x0;
}

int p_try_isra_name(struct p_isra_argument *p_isra_arg) {

   return P_SYM(p_kallsyms_on_each_symbol)(p_find_isra_name, p_isra_arg);
}

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
   P_SYM(p_kallsyms_on_each_symbol) = (int (*)(int (*)(void *, const char *, struct module *,
                                              unsigned long), void *))
                                       P_SYM(p_kallsyms_lookup_name)("kallsyms_on_each_symbol");

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

   P_SYM(p_kallsyms_on_each_symbol) = kallsyms_on_each_symbol;

#endif

get_kallsyms_address_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <get_kallsyms_address> (p_ret => %d)\n",p_ret);

   return p_ret;
}
