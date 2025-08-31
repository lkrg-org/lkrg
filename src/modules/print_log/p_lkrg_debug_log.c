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

void __cyg_profile_func_enter(void *this_fn, void *call_site)
__attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *this_fn, void *call_site)
__attribute__((no_instrument_function));

#ifdef P_LKRG_DEBUG_BUILD
static struct p_addr_name {
    uintptr_t	addr;
    const char *name;
} p_addr_name_array[] = {
   P_LKRG_DEBUG_RULE(init_ed_task_cache),
   P_LKRG_DEBUG_RULE(destroy_ed_task_cache),
   P_LKRG_DEBUG_RULE(alloc_ed_task),
   P_LKRG_DEBUG_RULE(free_ed_task),
   P_LKRG_DEBUG_RULE(ed_task_add),
   P_LKRG_DEBUG_RULE(ed_task_del_current),
   P_LKRG_DEBUG_RULE(__ed_task_find_rcu),
   P_LKRG_DEBUG_RULE(__ed_task_current),
   P_LKRG_DEBUG_RULE(p_dump_task_f),
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

#ifdef LKRG_WITH_HIDE
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
