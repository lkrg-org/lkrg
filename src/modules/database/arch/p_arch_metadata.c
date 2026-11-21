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

   P_SYM_INIT(core_kernel_text)

#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H

   if (p_install_switch_idt_hook(0)) {
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
    * This lock is used in our hooks of arch_jump_label_transform() and
    * arch_jump_label_transform_apply().
    */
   p_lkrg_counter_lock_init(&p_jl_lock);

   /*
    * This is not an arch specific hook, but it's a good place to register it
    */
   if (p_install_arch_jump_label_transform_hook(0)) {
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform'");
      return P_LKRG_GENERAL_ERROR;
   }

#ifdef P_LKRG_CI_ARCH_JUMP_LABEL_TRANSFORM_APPLY_H
   /*
    * These symbols are used in our hook of arch_jump_label_transform_apply().
    */
#ifdef TEXT_POKE_MAX_OPCODE_SIZE
   P_SYM_INIT(text_poke_array)
#else
   P_SYM_INIT(tp_vec)
   P_SYM_INIT(tp_vec_nr)
#endif

   /*
    * This is not an arch specific hook, but it's a good place to register it
    */
   if (p_install_arch_jump_label_transform_apply_hook(0)) {
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform_apply'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_DYNAMIC_FTRACE)
   /*
    * These symbols are used in our hook of ftrace_modify_all_code().
    */
   P_SYM_INIT(ftrace_lock)
   P_SYM_INIT(ftrace_rec_iter_start)
   P_SYM_INIT(ftrace_rec_iter_next)
   P_SYM_INIT(ftrace_rec_iter_record)

   /*
    * Same for FTRACE
    */
   if (p_install_ftrace_modify_all_code_hook(0)) {
      p_print_log(P_LOG_FATAL, "Can't hook 'ftrace_modify_all_code'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_FUNCTION_TRACER)
   if (p_install_ftrace_enable_sysctl_hook(0)) {
      p_print_log(P_LOG_FATAL, "Can't hook 'ftrace_enable_sysctl'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

#if defined(CONFIG_HAVE_STATIC_CALL)
   /*
    * This lock is used in our hook of arch_static_call_transform().
    */
   p_lkrg_counter_lock_init(&p_static_call_spinlock);

   if (p_install_arch_static_call_transform_hook(0)) {
      p_print_log(P_LOG_FATAL, "Can't hook 'arch_jump_label_transform'");
      return P_LKRG_GENERAL_ERROR;
   }
#endif

   return P_LKRG_SUCCESS;

p_sym_error:
   return P_LKRG_GENERAL_ERROR;
}


int p_unregister_arch_metadata(void) {

   /*
    * Some hooks take a lock in their entry handler and only release it in their
    * return handler: the hooks of ftrace_modify_all_code() and switch_idt()
    * take p_db_lock, and the hook of arch_static_call_transform() takes
    * p_static_call_spinlock. Once a hook is removed, its return handler doesn't
    * run for the calls of the hooked function that are still in progress, which
    * would leave the lock held forever.
    *
    * As such, disable those hooks and wait for the calls in progress to return
    * before removing them. A disabled hook's entry handler is no longer called,
    * while its return handler still runs for the calls in progress.
    *
    * The jump label hooks take p_jl_lock the same way, but they're left alone.
    * Only their own entry handlers wait for that lock, and a given kernel only
    * calls one of the two hooked functions, so nothing waits for it once that
    * hook is removed.
    */
#if defined(CONFIG_DYNAMIC_FTRACE)
   p_disable_ftrace_modify_all_code_hook();
#endif
#ifdef P_LKRG_RUNTIME_CODE_INTEGRITY_SWITCH_IDT_H
   p_disable_switch_idt_hook();
#endif
#if defined(CONFIG_HAVE_STATIC_CALL)
   p_disable_arch_static_call_transform_hook();
#endif

   /*
    * Wait for the entry handlers that are already running to finish. They run
    * with preemption disabled, which synchronize_rcu() is only guaranteed to
    * wait for since 4.20. RHEL 8.2 and later have that change too, and don't
    * have synchronize_sched() anymore.
    */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0) || \
   (defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 2))
   synchronize_rcu();
#else
   synchronize_sched();
#endif

   /*
    * Wait for the calls in progress to release both locks. p_db_lock must be
    * taken with interrupts enabled here, since the call that holds it may be
    * waiting for every CPU to handle an IPI.
    */
#if defined(CONFIG_HAVE_STATIC_CALL)
   while (p_lkrg_counter_lock_val_read(&p_static_call_spinlock))
      schedule();
#endif
   spin_lock(&p_db_lock);
   spin_unlock(&p_db_lock);

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
