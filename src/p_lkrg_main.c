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

int (*p_freeze_processes)(void) = 0x0;
void (*p_thaw_processes)(void) = 0x0;

/*
 * Main entry point for the module - initialization.
 */
static int __init p_lkrg_register(void) {

   int p_ret = P_LKRG_SUCCESS;
   char p_cpu = 0x0;

   p_print_log(P_LKRG_CRIT, "Loading LKRG...\n");

   /*
    * Generate random SipHash key
    */
   p_global_siphash_key.p_low  = (uint64_t)get_random_long();
   p_global_siphash_key.p_high = (uint64_t)get_random_long();

   memset(&p_lkrg_global_ctrl,0x0,sizeof(p_lkrg_global_ctrl_struct));
   p_lkrg_global_ctrl.p_timestamp = 15;        // seconds
   if (p_init_log_level >= P_LOG_LEVEL_MAX)
      p_lkrg_global_ctrl.p_log_level = P_LOG_LEVEL_MAX-1;      // Max
   else
      p_lkrg_global_ctrl.p_log_level = p_init_log_level;
   p_lkrg_global_ctrl.p_block_modules = 0x0;   // Do NOT block loading new modules
   p_lkrg_global_ctrl.p_hide_module   = 0x0;   // We are initially not hidden
   p_lkrg_global_ctrl.p_clean_message = 0x1;   // By default print "System is clean!" message

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

   p_freeze_processes = (int (*)(void))p_kallsyms_lookup_name("freeze_processes");

   if (!p_freeze_processes) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'freeze_processes' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   p_thaw_processes = (void (*)(void))p_kallsyms_lookup_name("thaw_processes");

   if (!p_thaw_processes) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'thaw_processes' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   // Freeze all non-kernel processes
   while (p_freeze_processes())
      schedule();

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
             "Can't initialize offloading cache :(\n");
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
   p_cpu = 0x1;

   if (p_register_comm_channel()) {
      p_print_log(P_LKRG_CRIT,
             "Can't initialize communication channel (sysctl) :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   p_integrity_timer();
   p_register_notifiers();
   p_lkrg_global_ctrl.p_random_events = 0x1;

#ifdef CONFIG_X86
   if (P_IS_SMEP_ENABLED(p_pcfi_CPU_flags))
      p_lkrg_global_ctrl.p_smep_panic = 0x1;
   else
      p_print_log(P_LKRG_ERR,
             "System does NOT support SMEP. LKRG can't enforece smep_panic :(\n");
#endif

   mutex_lock(&module_mutex);
   if (p_lkrg_global_ctrl.p_hide_module) {
      p_hide_itself();
   }
   mutex_unlock(&module_mutex);

   p_print_log(P_LKRG_CRIT,
          "LKRG initialized successfully!\n");

   p_ret = P_LKRG_SUCCESS;

p_main_error:

   if (p_ret != P_LKRG_SUCCESS) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
      if (p_cpu)
         unregister_hotcpu_notifier(&p_cpu_notifier);
#else
      if (p_cpu) {
         cpu_notifier_register_begin();
         __unregister_hotcpu_notifier(&p_cpu_notifier);
         cpu_notifier_register_done();
      }
#endif
#else
      if (p_cpu)
         cpuhp_remove_state_nocalls(p_hot_cpus);
#endif

      p_exploit_detection_exit();
      p_deregister_module_notifier();
      p_offload_cache_delete();
      if (p_db.p_CPU_metadata_array) {
         kzfree(p_db.p_CPU_metadata_array);
         p_db.p_CPU_metadata_array = NULL;
      }
   }

   // Thaw all non-kernel processes
   p_thaw_processes();

   return p_ret;
}

/*
 * This function normally should never be called - unloading module cleanup
 */
static void __exit p_lkrg_deregister(void) {

   p_print_log(P_LKRG_CRIT, "Unloading LKRG...\n");

#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_DBG,
          "I should never be here! This operation probably is going to break your system! Goodbye ;)\n");
#endif

   // Freeze all non-kernel processes
   while (p_freeze_processes())
      schedule();

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

   p_exploit_detection_exit();
   p_deregister_module_notifier();

   p_offload_cache_delete();
   p_unregister_arch_metadata();

   if (p_db.p_CPU_metadata_array)
      kzfree(p_db.p_CPU_metadata_array);

   // Thaw all non-kernel processes
   p_thaw_processes();

   p_print_log(P_LKRG_CRIT, "LKRG unloaded!\n");
}


module_init(p_lkrg_register);
module_exit(p_lkrg_deregister);

module_param(p_init_log_level, uint, 0000);
MODULE_PARM_DESC(p_init_log_level, "Logging level init value [1 (alive) is default]");

MODULE_AUTHOR("Adam 'pi3' Zabrocki (http://pi3.com.pl)");
MODULE_DESCRIPTION("pi3's Linux kernel Runtime Guard");
MODULE_LICENSE("GPL v2");
