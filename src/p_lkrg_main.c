/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Main module
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "p_lkrg_main.h"

unsigned int p_init_log_level = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
static enum cpuhp_state p_hot_cpus;
#endif

/*
 * Main entry point for the module - initialization.
 */
static int __init p_lkrg_register(void) {

   int p_ret = P_LKRG_SUCCESS;


   memset(&p_lkrg_global_ctrl,0x0,sizeof(p_lkrg_global_ctrl_struct));
   p_lkrg_global_ctrl.p_timestamp = 15;        // seconds
   if (p_init_log_level >= P_LOG_LEVEL_MAX)
      p_lkrg_global_ctrl.p_log_level = P_LOG_LEVEL_MAX-1;      // Max
   else
      p_lkrg_global_ctrl.p_log_level = p_init_log_level;
   p_lkrg_global_ctrl.p_block_modules = 0x0;   // Do NOT block loading new modules
   p_lkrg_global_ctrl.p_hide_module   = 0x0;   // We are initially not hidden

   if (get_kallsyms_address() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
             "Can't find kallsyms_lookup_name() function address! Exiting...\n");
      return P_LKRG_RESOLVER_ERROR;
   }
#ifdef P_LKRG_DEBUG
     else {
        p_print_log(P_LKRG_DBG,
               "kallsyms_lookup_name() => 0x%lx\n",(long)p_kallsyms_lookup_name);
     }
#endif
   /*
    * First, we need to plant *kprobes... Before DB is created!
    */
   if (p_exploit_detection_init()) {
      p_print_log(P_LKRG_CRIT,
             "Can't initialize exploit detection features! Exiting...\n");
      p_ret = P_LKRG_EXPLOIT_DETECTION_ERROR;
      goto p_main_error;
   }

   if (p_offload_cache_init()) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t initialize offloading cache :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   /*
    * Initialize kmod module
    */
   if (p_kmod_init()) {
      p_print_log(P_LKRG_CRIT,
             "Can't initialize kernel modules handling! Exiting...\n");
      p_ret = P_LKRG_KMOD_ERROR;
      goto p_main_error;
   }

   if (p_create_database() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
             "Can't create database! Exiting...\n");
      p_ret = P_LKRG_DATABASE_ERROR;
      goto p_main_error;
   }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
   register_hotcpu_notifier(&p_cpu_notifier);
#else
   cpu_notifier_register_begin();
   __register_hotcpu_notifier(&p_cpu_notifier);
   cpu_notifier_register_done();
#endif
#else
   if ( (p_hot_cpus = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
                         "x86/p_lkrg:online",
                         p_cpu_online_action,
                         p_cpu_dead_action)) < 0) {
      p_print_log(P_LKRG_CRIT,
             "Can't register hot CPU plug[in/out] handler! Exiting...\n");
      p_ret = P_LKRG_HPCPU_ERROR;
      goto p_main_error;
   }
#endif

   if (p_register_comm_channel()) {
      p_print_log(P_LKRG_CRIT,
             "Can\'t initialize communication channel (sysctl) :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   p_integrity_timer();
   p_register_notifiers();

   mutex_lock(&module_mutex);
   if (p_lkrg_global_ctrl.p_hide_module) {
      p_hide_itself();
   }
   mutex_unlock(&module_mutex);

   return P_LKRG_SUCCESS;

p_main_error:

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
   unregister_hotcpu_notifier(&p_cpu_notifier);
#else
   cpu_notifier_register_begin();
   __unregister_hotcpu_notifier(&p_cpu_notifier);
   cpu_notifier_register_done();
#endif
#else
   cpuhp_remove_state_nocalls(p_hot_cpus);
#endif

   p_deregister_module_notifier();
   if (p_db.p_IDT_MSR_CRx_array)
      kzfree(p_db.p_IDT_MSR_CRx_array);
   p_offload_cache_delete();
   p_exploit_detection_exit();

   return p_ret;
}

/*
 * This function normally should never be called - unloading module cleanup
 */
static void __exit p_lkrg_deregister(void) {

#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_DBG,
          "I should never be here! This operation probably is going to break your system! Goodbye ;)\n");
#endif

   del_timer(&p_timer);
   p_deregister_notifiers();
   p_deregister_comm_channel();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
   unregister_hotcpu_notifier(&p_cpu_notifier);
#else
   cpu_notifier_register_begin();
   __unregister_hotcpu_notifier(&p_cpu_notifier);
   cpu_notifier_register_done();
#endif
#else
   cpuhp_remove_state_nocalls(p_hot_cpus);
#endif

   p_deregister_module_notifier();

   kzfree(p_db.p_IDT_MSR_CRx_array);
   p_offload_cache_delete();
   p_exploit_detection_exit();

}


module_init(p_lkrg_register);
module_exit(p_lkrg_deregister);

module_param(p_init_log_level, uint, 0000);
MODULE_PARM_DESC(p_init_log_level, "Logging level init value [1 (alive) is default]");

MODULE_AUTHOR("Adam 'pi3' Zabrocki (http://pi3.com.pl)");
MODULE_DESCRIPTION("pi3's Linux kernel Runtime Guard");
MODULE_LICENSE("GPL"); // Don't think so...
