/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Debug module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 14.V.2020
 *
 * Author:
 *  - Mariusz Zaborski (https://oshogbo.vexillium.org/)
 *
 */

#include "../../p_lkrg_main.h"
#include "../database/p_database.h"

#define P_LKRG_DEBUG_RULE(fname) { (uintptr_t)fname, #fname }
#define P_LKRG_DEBUG_RULE_KPROBE(fname)                        \
   P_LKRG_DEBUG_RULE(fname##_entry),                           \
   P_LKRG_DEBUG_RULE(fname##_ret)

void __cyg_profile_func_enter(void *this_fn, void *call_site)
__attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *this_fn, void *call_site)
__attribute__((no_instrument_function));

#ifdef P_LKRG_DEBUG_BUILD
static struct p_addr_name {
    uintptr_t	addr;
    const char *name;
} p_addr_name_array[] = {
   P_LKRG_DEBUG_RULE(p_rb_add_ed_pid),
   P_LKRG_DEBUG_RULE(p_rb_del_ed_pid),
   P_LKRG_DEBUG_RULE(p_init_rb_ed_pids),
   P_LKRG_DEBUG_RULE(p_delete_rb_ed_pids),
   P_LKRG_DEBUG_RULE(p_dump_task_f),
   P_LKRG_DEBUG_RULE(p_remove_task_pid_f),
   P_LKRG_DEBUG_RULE(p_ed_enforce_validation),
   P_LKRG_DEBUG_RULE(p_ed_enforce_validation_paranoid),
   P_LKRG_DEBUG_RULE(p_exploit_detection_init),
   P_LKRG_DEBUG_RULE(p_exploit_detection_exit),
   P_LKRG_DEBUG_RULE(p_install_hook),
   P_LKRG_DEBUG_RULE(p_uninstall_hook),
   P_LKRG_DEBUG_RULE(p_kmod_init),
   P_LKRG_DEBUG_RULE(p_kmod_hash),
   P_LKRG_DEBUG_RULE(p_offload_cache_init),
   P_LKRG_DEBUG_RULE(p_offload_cache_delete),
   P_LKRG_DEBUG_RULE(p_integrity_timer),
   P_LKRG_DEBUG_RULE(p_offload_work),
   P_LKRG_DEBUG_RULE(p_check_integrity),
   P_LKRG_DEBUG_RULE(p_register_comm_channel),
   P_LKRG_DEBUG_RULE(p_deregister_comm_channel),
   P_LKRG_DEBUG_RULE(p_get_cpus),
   P_LKRG_DEBUG_RULE(p_cmp_cpus),
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
   P_LKRG_DEBUG_RULE(p_cpu_callback),
#endif
   P_LKRG_DEBUG_RULE(p_cpu_online_action),
   P_LKRG_DEBUG_RULE(p_cpu_dead_action),
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
   P_LKRG_DEBUG_RULE(p_install_switch_idt_hook),
   P_LKRG_DEBUG_RULE(p_uninstall_switch_idt_hook),
#endif
   P_LKRG_DEBUG_RULE(p_register_arch_metadata),
   P_LKRG_DEBUG_RULE(p_unregister_arch_metadata),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
   P_LKRG_DEBUG_RULE(p_install_arch_jump_label_transform_hook),
   P_LKRG_DEBUG_RULE(p_uninstall_arch_jump_label_transform_hook),
   P_LKRG_DEBUG_RULE(p_install_arch_jump_label_transform_apply_hook),
   P_LKRG_DEBUG_RULE(p_uninstall_arch_jump_label_transform_apply_hook),
#endif
   P_LKRG_DEBUG_RULE(hash_from_ex_table),
   P_LKRG_DEBUG_RULE(hash_from_kernel_stext),
   P_LKRG_DEBUG_RULE(hash_from_kernel_rodata),
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
   P_LKRG_DEBUG_RULE(hash_from_iommu_table),
#endif
   P_LKRG_DEBUG_RULE(hash_from_CPU_data),
   P_LKRG_DEBUG_RULE(p_create_database),
   P_LKRG_DEBUG_RULE(p_register_notifiers),
   P_LKRG_DEBUG_RULE(p_deregister_notifiers),
   P_LKRG_DEBUG_RULE(p_hide_itself),

#ifdef P_LKRG_UNHIDE
   P_LKRG_DEBUG_RULE(p_unhide_itself),
#endif

   P_LKRG_DEBUG_RULE(get_kallsyms_address),

#ifdef CONFIG_X86
   P_LKRG_DEBUG_RULE(p_read_msr),
   P_LKRG_DEBUG_RULE(p_dump_x86_metadata),
#endif

#if defined(CONFIG_ARM)
   P_LKRG_DEBUG_RULE(p_dump_arm_metadata),
#endif

#if defined(CONFIG_ARM64)
   P_LKRG_DEBUG_RULE(p_dump_arm64_metadata),
#endif

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
   P_LKRG_DEBUG_RULE_KPROBE(p_cap_task_prctl),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_capset),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setuid),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setregid),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setns),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_unshare),
   P_LKRG_DEBUG_RULE_KPROBE(p_generic_permission),
   P_LKRG_DEBUG_RULE_KPROBE(p_scm_send),
#if defined(CONFIG_SECCOMP)
   P_LKRG_DEBUG_RULE_KPROBE(p_seccomp),
#endif
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setresgid),
   P_LKRG_DEBUG_RULE_KPROBE(p_security_ptrace_access),
   P_LKRG_DEBUG_RULE_KPROBE(p_compat_sys_add_key),
   P_LKRG_DEBUG_RULE_KPROBE(p_compat_sys_capset),
   P_LKRG_DEBUG_RULE_KPROBE(p_compat_sys_keyctl),
   P_LKRG_DEBUG_RULE_KPROBE(p_compat_sys_request_key),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setfsgid),
   P_LKRG_DEBUG_RULE_KPROBE(p_call_usermodehelper_exec),
   P_LKRG_DEBUG_RULE_KPROBE(p_set_current_groups),
#if P_OVL_OVERRIDE_SYNC_MODE
   P_LKRG_DEBUG_RULE_KPROBE(p_ovl_override_sync),
#endif
   P_LKRG_DEBUG_RULE_KPROBE(p_revert_creds),
   P_LKRG_DEBUG_RULE_KPROBE(p_override_creds),
   P_LKRG_DEBUG_RULE_KPROBE(p_security_bprm_committing_creds),
   // Next function does not have matching entry one.
   P_LKRG_DEBUG_RULE(p_security_bprm_committed_creds_ret),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setresuid),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_keyctl),
   P_LKRG_DEBUG_RULE_KPROBE(p_key_change_session_keyring),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_add_key),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_request_key),
   P_LKRG_DEBUG_RULE_KPROBE(p_capable),
   P_LKRG_DEBUG_RULE_KPROBE(p_sel_write_enforce),
   P_LKRG_DEBUG_RULE_KPROBE(p_pcfi___queue_work),
   P_LKRG_DEBUG_RULE_KPROBE(p_pcfi_schedule),
   P_LKRG_DEBUG_RULE_KPROBE(p_pcfi_lookup_fast),
   P_LKRG_DEBUG_RULE_KPROBE(p_pcfi_mark_inode_dirty),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setreuid),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setgid),
   P_LKRG_DEBUG_RULE_KPROBE(p_call_usermodehelper),
   P_LKRG_DEBUG_RULE_KPROBE(p_x32_sys_keyctl),
   P_LKRG_DEBUG_RULE_KPROBE(p_sys_setfsuid),
   P_LKRG_DEBUG_RULE_KPROBE(p_do_exit),
   P_LKRG_DEBUG_RULE_KPROBE(p_wake_up_new_task),
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
   P_LKRG_DEBUG_RULE_KPROBE(p_switch_idt),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
   P_LKRG_DEBUG_RULE_KPROBE(p_arch_jump_label_transform),
   P_LKRG_DEBUG_RULE_KPROBE(p_arch_jump_label_transform_apply),
#endif
#endif

   // Disable to noisy.
   // P_LKRG_DEBUG_RULE(p_ed_enforce_pcfi),
   // P_LKRG_DEBUG_RULE(p_rb_find_ed_pid),
   // P_LKRG_DEBUG_RULE(p_validate_task_f),
   // P_LKRG_DEBUG_RULE(p_ed_wq_valid_cache_init),
   // P_LKRG_DEBUG_RULE(p_ed_pcfi_validate_sp),

   { 0, NULL }
};

void __cyg_profile_func_enter(void *func, void *caller) {

   struct p_addr_name *it;

   for (it = p_addr_name_array; it->name != NULL; it++) {
      if (it->addr == (uintptr_t)func) {
         p_debug_log(P_LOG_FLOOD,
            "Entering function <%s>", it->name);
         break;
      }
   }
}

void __cyg_profile_func_exit(void *func, void *caller) {

   struct p_addr_name *it;

   for (it = p_addr_name_array; it->name != NULL; it++) {
      if (it->addr == (uintptr_t)func) {
         p_debug_log(P_LOG_FLOOD,
            "Leaving function <%s>", it->name);
		   break;
      }
   }
}
#endif /* P_LKRG_DEBUG_BUILD */
