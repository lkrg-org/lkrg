/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Handle *_JUMP_LABEL self-modifying code.
 *    Hook 'arch_jump_label_transform_apply' function.
 *
 * Notes:
 *  - Linux kernel is heavily consuming *_JUMP_LABEL (if enabled). Most of the
 *    Linux distributions provide kernel with these options compiled. It makes
 *    Linux kernel being self-modifying code. It is very troublesome for this
 *    project. We are relying on comparing hashes from the specific memory
 *    regions and by design self-modifications break this functionality.
 *  - We are hooking into low-level *_JUMP_LABEL functions to be able to
 *    monitor whenever new modification is on the way.
 *
 * Caveats:
 *  - Since kernel 5.3 Linux has support for 'batch mode' *_JUMP_LABEL.
 *    Let's handle that as well.
 *
 *    https://lore.kernel.org/patchwork/patch/1064287/
 *
 * Timeline:
 *  - Created: 31.X.2019
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#ifdef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H

static unsigned long p_jl_batch_addr[P_TP_VEC_MAX];
static unsigned int p_jl_batch_nr;

char p_arch_jump_label_transform_apply_kretprobe_state = 0;

static struct kretprobe p_arch_jump_label_transform_apply_kretprobe = {
    .kp.symbol_name = "arch_jump_label_transform_apply",
    .handler = p_arch_jump_label_transform_apply_ret,
    .entry_handler = p_arch_jump_label_transform_apply_entry,
    .data_size = sizeof(struct p_arch_jump_label_transform_apply_data),
    /* Probe up to 40 instances concurrently. */
    .maxactive = 40,
};


notrace int p_arch_jump_label_transform_apply_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   int p_nr = *P_SYM(p_tp_vec_nr);
   int p_cnt = 0;
   p_text_poke_loc *p_tmp;
   unsigned long p_flags;

   p_debug_kprobe_log(
          "p_arch_jump_label_transform_apply_entry: comm[%s] Pid:%d",current->comm,current->pid);

   do {
      p_lkrg_counter_lock_lock(&p_jl_lock, &p_flags);
      if (!p_lkrg_counter_lock_val_read(&p_jl_lock))
         break;
      p_lkrg_counter_lock_unlock(&p_jl_lock, &p_flags);
      cpu_relax();
   } while(1);
   p_lkrg_counter_lock_val_inc(&p_jl_lock);
   p_lkrg_counter_lock_unlock(&p_jl_lock, &p_flags);

   p_print_log(P_LOG_WATCH,
               "[JUMP_LABEL <batch mode>] New modifications => %d",p_nr);

   for (p_jl_batch_nr = 0; p_cnt < p_nr; p_cnt++) {
      p_tmp = (p_text_poke_loc *)&P_SYM(p_tp_vec)[p_jl_batch_nr*sizeof(p_text_poke_loc)];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
      if ( (p_tmp->opcode == CALL_INSN_OPCODE
            || p_tmp->opcode == JMP32_INSN_OPCODE
            || p_tmp->opcode == INT3_INSN_OPCODE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
            || p_tmp->opcode == RET_INSN_OPCODE
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
            || p_tmp->opcode == JMP8_INSN_OPCODE
#endif
            ) &&
          p_tmp->rel_addr) {
#else
      if ( (p_tmp->len == 5
#if P_LKRG_KERNEL_HAS_VAR_LEN_JUMP_LABEL
            || p_tmp->len == 2
#endif
            ) &&
          p_tmp->addr
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0) || \
   (defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 3)) || \
   (defined(CONFIG_SUSE_PRODUCT_CODE) && CONFIG_SUSE_PRODUCT_CODE == 1)
          && p_tmp->opcode) {
#else
          && p_tmp->detour) {
#endif

#endif
         p_jl_batch_addr[p_jl_batch_nr++] =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
                  (unsigned long)p_tmp->rel_addr +
                  (unsigned long)p_db.kernel_stext.p_addr;
#else
                  (unsigned long)p_tmp->addr;
#endif
      }
   }

   /* A dump_stack() here will give a stack backtrace */
   return 0;
}


notrace int p_arch_jump_label_transform_apply_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   struct module *p_module = NULL;
   unsigned int p_cnt;
   unsigned int p_tmp,p_tmp2;
   unsigned char p_flag = 0;
   unsigned int p_text = 0;
   unsigned int p_mod = 0;
//   DECLARE_BITMAP(p_mod_mask, p_db.p_module_list_nr);

   bitmap_zero(p_db.p_jump_label.p_mod_mask, p_db.p_module_list_nr);

   for (p_cnt = 0; p_cnt < p_jl_batch_nr; p_cnt++) {

      if (P_SYM(p_core_kernel_text)(p_jl_batch_addr[p_cnt])) {

         p_text++;

      } else if ( (p_module = LKRG_P_MODULE_TEXT_ADDRESS(p_jl_batch_addr[p_cnt])) != NULL) {

         for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
            if (p_db.p_module_list_array[p_tmp].p_mod == p_module) {

               /*
                * OK, we found this module on our internal tracking list.
                * Set bit in bitmask
                */
               set_bit(p_tmp, p_db.p_jump_label.p_mod_mask);
               p_mod++;
               break;
            }
         }

      } else {
         /*
          * FTRACE might generate dynamic trampoline which is not part of .text section.
          * This is not abnormal situation anymore.
          */
         p_print_log(P_LOG_WATCH,
                     "[JUMP_LABEL <batch mode>] Not a .text section! [0x%lx]",p_jl_batch_addr[p_cnt]);
      }
   }

   if (p_text) {
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
                  "[JUMP_LABEL <batch mode>] Updating kernel core .text section hash!");
   }

   if (p_mod) {
      for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
         if (test_bit(p_tmp, p_db.p_jump_label.p_mod_mask)) {

            /*
             * OK, we found this module on our internal tracking list.
             * Update it's hash
             */

            p_module = p_db.p_module_list_array[p_tmp].p_mod;

            p_print_log(P_LOG_WATCH,
                        "[JUMP_LABEL <batch mode>] Updating module's core .text section hash module[%s : 0x%lx]!",
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
                           "[JUMP_LABEL <batch mode>] Updated module's list hash for module[%s] but can't find the same module in KOBJs list!",
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

   p_db.p_jump_label.p_state = P_JUMP_LABEL_NONE;

   p_lkrg_counter_lock_val_dec(&p_jl_lock);

   return 0;
}


int p_install_arch_jump_label_transform_apply_hook(void) {

   int p_tmp;

   P_SYM_INIT(tp_vec, struct text_poke_loc **)
   P_SYM_INIT(tp_vec_nr, int *)

// DEBUG
   p_debug_log(P_LOG_DEBUG, "<p_install_arch_jump_label_transform_apply_hook> "
                           "p_tp_vec[0x%lx] p_tp_vec_nr[0x%lx]",
                           (unsigned long)P_SYM(p_tp_vec),
                           (unsigned long)P_SYM(p_tp_vec_nr));

   if ( (p_tmp = register_kretprobe(&p_arch_jump_label_transform_apply_kretprobe)) != 0) {
      p_print_log(P_LOG_FATAL, "[kretprobe] register_kretprobe() for <%s> failed! [err=%d]",
                  p_arch_jump_label_transform_apply_kretprobe.kp.symbol_name,
                  p_tmp);
      return P_LKRG_GENERAL_ERROR;
   }
   p_print_log(P_LOG_WATCH, "Planted [kretprobe] <%s> at: 0x%lx",
               p_arch_jump_label_transform_apply_kretprobe.kp.symbol_name,
               (unsigned long)p_arch_jump_label_transform_apply_kretprobe.kp.addr);
   p_arch_jump_label_transform_apply_kretprobe_state = 1;

   return P_LKRG_SUCCESS;

p_sym_error:
   return P_LKRG_GENERAL_ERROR;
}


void p_uninstall_arch_jump_label_transform_apply_hook(void) {

   if (!p_arch_jump_label_transform_apply_kretprobe_state) {
      p_print_log(P_LOG_WATCH, "[kretprobe] <%s> at 0x%lx is NOT installed",
                  p_arch_jump_label_transform_apply_kretprobe.kp.symbol_name,
                  (unsigned long)p_arch_jump_label_transform_apply_kretprobe.kp.addr);
   } else {
      unregister_kretprobe(&p_arch_jump_label_transform_apply_kretprobe);
      p_print_log(P_LOG_WATCH, "Removing [kretprobe] <%s> at 0x%lx nmissed[%d]",
                  p_arch_jump_label_transform_apply_kretprobe.kp.symbol_name,
                  (unsigned long)p_arch_jump_label_transform_apply_kretprobe.kp.addr,
                  p_arch_jump_label_transform_apply_kretprobe.nmissed);
      p_arch_jump_label_transform_apply_kretprobe_state = 0;
   }
}

#endif
