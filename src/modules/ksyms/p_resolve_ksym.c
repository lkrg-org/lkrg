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

//unsigned long (*p_kallsyms_lookup_name)(const char *name) = 0;


static int p_find_isra_name(void *p_isra_argg, const char *name,
                            struct module *mod, unsigned long addr) {

   struct p_isra_argument *p_isra_arg = (struct p_isra_argument *)p_isra_argg;
   char p_buf[0x100];
   char p_buf2[0x100];

   snprintf(p_buf, sizeof(p_buf), "%s.isra.", p_isra_arg->p_name);
   snprintf(p_buf2, sizeof(p_buf2), "%s.constprop.", p_isra_arg->p_name);
   if (strncmp(p_buf, name, strlen(p_buf)) == 0) {
      p_print_log(P_LOG_ISSUE, "Found ISRA version of function <%s>", name);
      if ( (p_isra_arg->p_isra_name = kzalloc(strlen(name)+1, GFP_KERNEL)) == NULL) {
         p_print_log(P_LOG_FAULT, "Can't allocate memory");
         return 0;
      }
      memcpy(p_isra_arg->p_isra_name, name, strlen(name));
      return addr;
   } else if (strncmp(p_buf2, name, strlen(p_buf2)) == 0) {
      p_print_log(P_LOG_ISSUE, "Found CONSTPROP version of function <%s>", name);
      if ( (p_isra_arg->p_isra_name = kzalloc(strlen(name)+1, GFP_KERNEL)) == NULL) {
         p_print_log(P_LOG_FAULT, "Can't allocate memory");
         return 0;
      }
      memcpy(p_isra_arg->p_isra_name, name, strlen(name));
      return addr;
   }

   return 0;
}

int p_try_isra_name(struct p_isra_argument *p_isra_arg) {

   return P_SYM(p_kallsyms_on_each_symbol)(p_find_isra_name, p_isra_arg);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

static int p_tmp_kprobe_handler(struct kprobe *p_ri, struct pt_regs *p_regs) {
   return 0;
}

#else

static int p_lookup_syms_hack(void *unused, const char *name,
                              struct module *mod, unsigned long addr) {

   if (strcmp("kallsyms_lookup_name", name) == 0) {
      P_SYM(p_kallsyms_lookup_name) = (unsigned long (*)(const char*)) (addr);
      return addr;
   }

   return 0;
}

#endif

long get_kallsyms_address(void) {

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
   struct kprobe p_kprobe;
#endif
   int p_ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

   /*
    * Linux kernel 5.7+ no longer exports the kallsyms_lookup_name symbol for
    * use from modules.  We reuse the workaround originally introduced in the
    * LTTng module to access that symbol anyway.
    */
   memset(&p_kprobe, 0, sizeof(p_kprobe));
   p_kprobe.pre_handler = p_tmp_kprobe_handler;
   p_kprobe.symbol_name = "kallsyms_lookup_name";
   if ( (p_ret = register_kprobe(&p_kprobe)) < 0) {
      p_print_log(P_LOG_FAULT, "[get_kallsyms_address] register_kprobe error [%d]", p_ret);
      return P_LKRG_GENERAL_ERROR;
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

   if ( (p_ret = kallsyms_on_each_symbol(p_lookup_syms_hack,NULL)) == 0) {
      p_debug_log(P_LOG_DEBUG,
             "kallsyms_on_each_symbol error :(");
      return P_LKRG_GENERAL_ERROR;
   }

   p_print_log(P_LOG_WATCH,
          "kallsyms_on_each_symbol() returned => 0x%x [0x%lx]",
          p_ret,
          (unsigned long)P_SYM(p_kallsyms_lookup_name));

   P_SYM(p_kallsyms_on_each_symbol) = kallsyms_on_each_symbol;

#endif

   return P_LKRG_SUCCESS;
}
