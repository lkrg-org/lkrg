/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle dynamic FTRACE self-modifying code.
 *    Hook 'ftrace_modify_all_code' function.
 *
 * Notes:
 *  - Linux kernel might be self-modifying using dynamic FTRACE.
 *    Most of the Linux distributions provide kernel with FTRACE enabled.
 *    It can dynamically modify Linux kernel code. It is very troublesome
 *    for this project. We are relying on comparing hashes from the specific
 *    memory regions and by design self-modifications break this functionality.
 *  - We are hooking into low-level FTRACE functions to be able to monitor
 *    whenever new modification is on the way.
 *
 * Caveats:
 *  - None
 *
 * Timeline:
 *  - Created: 18.IX.2020
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#if defined(P_LKRG_FTRACE_MODIFY_ALL_CODE_H)

char p_ftrace_modify_all_code_kretprobe_state = 0;

static struct kretprobe p_ftrace_modify_all_code_kretprobe = {
    .kp.symbol_name = "ftrace_modify_all_code",
    .handler = p_ftrace_modify_all_code_ret,
    .entry_handler = p_ftrace_modify_all_code_entry,
    .data_size = sizeof(struct p_ftrace_modify_all_code_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};

/*
 * We do not need to protect this variables since ftrace_modify_all_code() is executed
 * under ftrace lock. LKRG is synchronizing with it...
 *
 * ... unless I overlooked some code-path...
 */
unsigned long p_ftrace_tmp_text;
unsigned int p_ftrace_tmp_mod;

/*
 * Prototype:
 *
 * static int ftrace_modify_all_code(unsigned long pc, unsigned long old,
 *                                   unsigned long new, bool validate)
 */
notrace int p_ftrace_modify_all_code_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   struct ftrace_rec_iter *p_iter;
   struct dyn_ftrace *p_rec;
   struct module *p_module = NULL;
   unsigned int p_tmp;
   int p_command = p_regs_get_arg1(p_regs);

   if (unlikely(!P_SYM(p_state_init)))
      return 0;

   spin_lock(&p_db_lock);
   p_ftrace_tmp_mod = p_ftrace_tmp_text = 0;
   /* text_mutex lock should do the sync work here... */
   bitmap_zero(p_db.p_jump_label.p_mod_mask, p_db.p_module_list_nr);

   if (p_command & FTRACE_UPDATE_TRACE_FUNC ||
       p_command & FTRACE_START_FUNC_RET ||
       p_command & FTRACE_STOP_FUNC_RET) {
      p_ftrace_tmp_text++;
   }

   p_for_ftrace_rec_iter(p_iter) {
      p_rec = P_SYM(p_ftrace_rec_iter_record)(p_iter);

      if (P_SYM(p_core_kernel_text)(p_rec->ip)) {

         p_ftrace_tmp_text++;

      } else if ( (p_module = LKRG_P_MODULE_TEXT_ADDRESS(p_rec->ip)) != NULL) {
         for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
            if (p_db.p_module_list_array[p_tmp].p_mod == p_module) {
               /*
                * OK, we found this module on our internal tracking list.
                * Set bit in bitmask
                */
               set_bit(p_tmp, p_db.p_jump_label.p_mod_mask);
               p_ftrace_tmp_mod++;
               break;
            }
         }

      } else {
         /*
          * FTRACE might generate dynamic trampoline which is not part of .text section.
          * This is not abnormal situation anymore.
          */
         p_print_log(P_LOG_WATCH,
                     "[FTRACE] Not a .text section! [0x%lx]",p_rec->ip);
      }
   }

   return 0;
}


notrace int p_ftrace_modify_all_code_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   unsigned int p_tmp,p_tmp2;
   unsigned char p_flag = 0;
   struct module *p_module = NULL;

   /*
    * Are we initialized?
    */
   if (unlikely(!P_SYM(p_state_init)))
      return 0;

   if (p_ftrace_tmp_text) {
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

      p_print_log(P_LOG_WATCH,
             "[FTRACE] Updating kernel core .text section hash!");

   }

   if (p_ftrace_tmp_mod) {

      for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
         if (test_bit(p_tmp, p_db.p_jump_label.p_mod_mask)) {

            /*
             * OK, we found this module on our internal tracking list.
             * Update it's hash
             */
            p_module = p_db.p_module_list_array[p_tmp].p_mod;

            p_print_log(P_LOG_WATCH,
                        "[FTRACE] Updating module's core .text section hash module[%s : 0x%lx]!",
                        p_db.p_module_list_array[p_tmp].p_name,
                        (unsigned long)p_db.p_module_list_array[p_tmp].p_mod);

            p_db.p_module_list_array[p_tmp].p_mod_core_text_hash =
                 p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array[p_tmp].p_module_core,
                                  (unsigned int)p_db.p_module_list_array[p_tmp].p_core_text_size);
            /*
             * Because we have modified individual module's hash, we need to update
             * 'global' module's list hash as well
             */
            p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                                       (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));


            /*
             * Because we update module's .text section hash we need to update KOBJs as well.
             */
            for (p_tmp2 = 0; p_tmp2 < p_db.p_module_kobj_nr; p_tmp2++) {
               if (p_db.p_module_kobj_array[p_tmp2].p_mod == p_module) {
                  p_db.p_module_kobj_array[p_tmp2].p_mod_core_text_hash =
                                   p_db.p_module_list_array[p_tmp].p_mod_core_text_hash;
                  p_flag = 1;
                  break;
               }
            }

            if (!p_flag) {
               p_print_log(P_LOG_FAULT,
                           "[FTRACE] Updated module's list hash for module[%s] but can't find the same module in KOBJs list!",
                           p_db.p_module_list_array[p_tmp].p_name);
               p_print_log(P_LOG_WATCH,"module[%s : 0x%lx]!",
                           p_db.p_module_list_array[p_tmp].p_name,
                           (unsigned long)p_db.p_module_list_array[p_tmp].p_mod);
            } else {

               /*
                * Because we have modified individual module's hash, we need to update
                * 'global' module's list hash as well
                */
               p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
            }
         }
      }
   }

   spin_unlock(&p_db_lock);

   return 0;
}


int p_install_ftrace_modify_all_code_hook(void) {

   int p_tmp;

   P_SYM_INIT(ftrace_lock, struct mutex *)
   P_SYM_INIT(ftrace_rec_iter_start, struct ftrace_rec_iter *(*)(void))
   P_SYM_INIT(ftrace_rec_iter_next, struct ftrace_rec_iter *(*)(struct ftrace_rec_iter *))
   P_SYM_INIT(ftrace_rec_iter_record, struct dyn_ftrace *(*)(struct ftrace_rec_iter *))

   if ( (p_tmp = register_kretprobe(&p_ftrace_modify_all_code_kretprobe)) != 0) {
      p_print_log(P_LOG_FATAL, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]",
                  p_ftrace_modify_all_code_kretprobe.kp.symbol_name,
                  p_tmp);
      return P_LKRG_GENERAL_ERROR;
   }
   p_print_log(P_LOG_WATCH, "Planted [kretprobe] <%s> at: 0x%lx",
               p_ftrace_modify_all_code_kretprobe.kp.symbol_name,
               (unsigned long)p_ftrace_modify_all_code_kretprobe.kp.addr);
   p_ftrace_modify_all_code_kretprobe_state = 1;

   return P_LKRG_SUCCESS;

p_sym_error:
   return P_LKRG_GENERAL_ERROR;
}


void p_uninstall_ftrace_modify_all_code_hook(void) {

   if (!p_ftrace_modify_all_code_kretprobe_state) {
      p_print_log(P_LOG_WATCH, "[kretprobe] <%s> at 0x%lx is NOT installed",
                  p_ftrace_modify_all_code_kretprobe.kp.symbol_name,
                  (unsigned long)p_ftrace_modify_all_code_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_ftrace_modify_all_code_kretprobe);
      p_print_log(P_LOG_WATCH, "Removing [kretprobe] <%s> at 0x%lx nmissed[%d]",
                  p_ftrace_modify_all_code_kretprobe.kp.symbol_name,
                  (unsigned long)p_ftrace_modify_all_code_kretprobe.kp.addr,
                  p_ftrace_modify_all_code_kretprobe.nmissed);
      p_ftrace_modify_all_code_kretprobe_state = 0;
   }
}

#endif
