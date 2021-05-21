/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Tracepoints: hook 'arch_static_call_transform' function.
 *
 * Notes:
 *  - Since kernel 5.10 tracepoints don't use JUMP_LABEL engine for .text
      kernel modifications.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 22.IV.2021
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#if defined(P_LKRG_CI_ARCH_STATIC_CALL_TRANSFORM_H)

static char p_arch_static_call_transform_kretprobe_state = 0;

static struct kretprobe p_arch_static_call_transform_kretprobe = {
    .kp.symbol_name = "arch_static_call_transform",
    .handler = p_arch_static_call_transform_ret,
    .entry_handler = p_arch_static_call_transform_entry,
    .data_size = sizeof(struct p_arch_static_call_transform_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};

static unsigned long p_tracepoint_tmp_text;
static struct module *p_module1;
static struct module *p_module2;
static unsigned int p_module1_idx;
static unsigned int p_module2_idx;

notrace int p_arch_static_call_transform_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   unsigned long p_site = p_regs_get_arg1(p_regs);
   unsigned long p_tramp = p_regs_get_arg2(p_regs);
   unsigned int p_tmp;

   p_debug_kprobe_log(
          "p_arch_static_call_transform_entry: comm[%s] Pid:%d\n",current->comm,current->pid);

   /*
    * We don't need to take any lock here because there can be only one instance of
    * 'arch_static_call_transform' function running at a time. It's being guarded in
    * a few ways by upper layer via 'static_call_lock', 'tracepoints_mutex' and 'event_mutex'
    */
   p_module1_idx = p_module2_idx = p_tracepoint_tmp_text = 0;
   p_module1 = p_module2 = NULL;

   if (p_tramp) {

      p_print_log(P_LKRG_INFO,
                  "[TRACEPOINT] New modification: code[0x%lx]!\n",
                  (unsigned long)p_tramp);

      if (P_SYM(p_core_kernel_text)(p_tramp)) {

         p_tracepoint_tmp_text++;

#ifdef P_LKRG_UNEXPORTED_MODULE_ADDRESS
      } else if ( (p_module1 = P_SYM(p_module_text_address)(p_tramp)) != NULL) {
#else
      } else if ( (p_module1 = __module_text_address(p_tramp)) != NULL) {
#endif
         for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
            if (p_db.p_module_list_array[p_tmp].p_mod == p_module1) {
               /*
                * OK, we found this module on our internal tracking list.
                */
               p_module1_idx = p_tmp;
               break;
            }
         }

      } else {
         /*
          * We shouldn't be here...
          */
         p_print_log(P_LKRG_ERR,
                     "[TRACEPOINT] Not a .text section! [0x%lx]\n",p_tramp);
      }
   }

   if (IS_ENABLED(CONFIG_HAVE_STATIC_CALL_INLINE) && p_site) {

      p_print_log(P_LKRG_INFO,
                  "[TRACEPOINT] New modification: code[0x%lx]!\n",
                  (unsigned long)p_site);

      if (P_SYM(p_core_kernel_text)(p_site)) {

         p_tracepoint_tmp_text++;

#ifdef P_LKRG_UNEXPORTED_MODULE_ADDRESS
      } else if ( (p_module2 = P_SYM(p_module_text_address)(p_site)) != NULL) {
#else
      } else if ( (p_module2 = __module_text_address(p_site)) != NULL) {
#endif
         for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
            if (p_db.p_module_list_array[p_tmp].p_mod == p_module2) {
               /*
                * OK, we found this module on our internal tracking list.
                */
               p_module2_idx = p_tmp;
               break;
            }
         }

      } else {
         /*
          * We shouldn't be here...
          */
         p_print_log(P_LKRG_ERR,
                     "[TRACEPOINT] Not a .text section! [0x%lx]\n",p_site);
      }
   }

   /* A dump_stack() here will give a stack backtrace */
   return 0;
}


notrace int p_arch_static_call_transform_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   unsigned int p_tmp;
   unsigned char p_flag = 0;

   if (p_tracepoint_tmp_text) {
      /*
       * We do not require to take any locks neither to copy entire .text section to temporary memory
       * since at this state it is static. Just recompute the hash.
       */
      p_db.kernel_stext.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_stext.p_addr,
                                                  (unsigned int)p_db.kernel_stext.p_size);
#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
      memcpy(p_db.kernel_stext_copy,p_db.kernel_stext.p_addr,p_db.kernel_stext.p_size);
      p_db.kernel_stext_copy[p_db.kernel_stext.p_size] = 0;
#endif

      p_print_log(P_LKRG_INFO,
             "[TRACEPOINT] Updating kernel core .text section hash!\n");

   }

   if (p_module1) {

      p_print_log(P_LKRG_INFO,
                  "[TRACEPOINT] Updating module's core .text section hash module[%s : 0x%lx]!\n",
                  p_db.p_module_list_array[p_module1_idx].p_name,
                  (unsigned long)p_db.p_module_list_array[p_module1_idx].p_mod);

      p_db.p_module_list_array[p_module1_idx].p_mod_core_text_hash =
                 p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array[p_module1_idx].p_module_core,
                                  (unsigned int)p_db.p_module_list_array[p_module1_idx].p_core_text_size);

      /*
       * Because we have modified individual module's hash, we need to update
       * 'global' module's list hash as well
       */
      p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                                 (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));


      /*
       * Because we update module's .text section hash we need to update KOBJs as well.
       */
      for (p_tmp = 0; p_tmp < p_db.p_module_kobj_nr; p_tmp++) {
         if (p_db.p_module_kobj_array[p_tmp].p_mod == p_module1) {
            p_db.p_module_kobj_array[p_tmp].p_mod_core_text_hash =
                             p_db.p_module_list_array[p_module1_idx].p_mod_core_text_hash;
            p_flag = 1;
            break;
         }
      }

      if (!p_flag) {
         p_print_log(P_LKRG_ERR,
                     "[TRACEPOINT] Updated module's list hash for module[%s] but can't find the same module in KOBJs list!\n",
                     p_db.p_module_list_array[p_module1_idx].p_name);
         p_print_log(P_LKRG_INFO,"module[%s : 0x%lx]!\n",
                     p_db.p_module_list_array[p_module1_idx].p_name,
                     (unsigned long)p_db.p_module_list_array[p_module1_idx].p_mod);
      } else {
         /*
          * Because we have modified individual module's hash, we need to update
          * 'global' module's list hash as well
          */
         p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                                    (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
      }
   }

   if (p_module2) {

      p_print_log(P_LKRG_INFO,
                  "[TRACEPOINT] Updating module's core .text section hash module[%s : 0x%lx]!\n",
                  p_db.p_module_list_array[p_module2_idx].p_name,
                  (unsigned long)p_db.p_module_list_array[p_module2_idx].p_mod);

      p_db.p_module_list_array[p_module2_idx].p_mod_core_text_hash =
                 p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array[p_module2_idx].p_module_core,
                                  (unsigned int)p_db.p_module_list_array[p_module2_idx].p_core_text_size);

      /*
       * Because we have modified individual module's hash, we need to update
       * 'global' module's list hash as well
       */
      p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                                 (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));


      /*
       * Because we update module's .text section hash we need to update KOBJs as well.
       */
      for (p_tmp = 0; p_tmp < p_db.p_module_kobj_nr; p_tmp++) {
         if (p_db.p_module_kobj_array[p_tmp].p_mod == p_module2) {
            p_db.p_module_kobj_array[p_tmp].p_mod_core_text_hash =
                             p_db.p_module_list_array[p_module2_idx].p_mod_core_text_hash;
            p_flag = 1;
            break;
         }
      }

      if (!p_flag) {
         p_print_log(P_LKRG_ERR,
                     "[TRACEPOINT] Updated module's list hash for module[%s] but can't find the same module in KOBJs list!\n",
                     p_db.p_module_list_array[p_module2_idx].p_name);
         p_print_log(P_LKRG_INFO,"module[%s : 0x%lx]!\n",
                     p_db.p_module_list_array[p_module2_idx].p_name,
                     (unsigned long)p_db.p_module_list_array[p_module2_idx].p_mod);
      } else {
         /*
          * Because we have modified individual module's hash, we need to update
          * 'global' module's list hash as well
          */
         p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                                    (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
      }
   }

   return 0;
}


int p_install_arch_static_call_transform_hook(void) {

   int p_tmp;

   if ( (p_tmp = register_kretprobe(&p_arch_static_call_transform_kretprobe)) != 0) {
      p_print_log(P_LKRG_ERR, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]\n",
                  p_arch_static_call_transform_kretprobe.kp.symbol_name,
                  p_tmp);
      return P_LKRG_GENERAL_ERROR;
   }
   p_print_log(P_LKRG_INFO, "Planted [kretprobe] <%s> at: 0x%lx\n",
               p_arch_static_call_transform_kretprobe.kp.symbol_name,
               (unsigned long)p_arch_static_call_transform_kretprobe.kp.addr);
   p_arch_static_call_transform_kretprobe_state = 1;

   return P_LKRG_SUCCESS;
}


void p_uninstall_arch_static_call_transform_hook(void) {

   if (!p_arch_static_call_transform_kretprobe_state) {
      p_print_log(P_LKRG_INFO, "[kretprobe] <%s> at 0x%lx is NOT installed\n",
                  p_arch_static_call_transform_kretprobe.kp.symbol_name,
                  (unsigned long)p_arch_static_call_transform_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_arch_static_call_transform_kretprobe);
      p_print_log(P_LKRG_INFO, "Removing [kretprobe] <%s> at 0x%lx nmissed[%d]\n",
                  p_arch_static_call_transform_kretprobe.kp.symbol_name,
                  (unsigned long)p_arch_static_call_transform_kretprobe.kp.addr,
                  p_arch_static_call_transform_kretprobe.nmissed);
      p_arch_static_call_transform_kretprobe_state = 0;
   }
}

#endif
