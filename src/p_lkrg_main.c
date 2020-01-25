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
unsigned int p_attr_init = 0x0;

p_ro_page p_ro __p_lkrg_read_only = {

#if !defined(CONFIG_ARM)
   .p_marker_np1 = P_LKRG_MARKER1,
#endif

   .p_lkrg_global_ctrl.ctrl = {
      .p_timestamp = 15,                  // timestamp
      .p_log_level = 3,                   // log_level
      .p_force_run = 0,                   // force_run
      .p_block_modules = 0,               // block_modules
      .p_hide_module = 0,                 // hide_module
      .p_clean_message = 0,               // clean_message
      .p_random_events = 0,               // random_events
      .p_ci_panic = 0,                    // ci_panic
#if defined(CONFIG_X86)
      .p_smep_panic = 0,                  // smep_panic
#endif
      .p_enforce_umh = 1,                 // enforce_umh
      .p_enforce_msr = 1,                 // enforce_msr
      .p_enforce_pcfi = P_PCFI_ENABLED    // enforce_pcfi
   },

#if !defined(CONFIG_ARM)
   .p_marker_np2 = P_LKRG_MARKER1,
   .p_marker_np3 = P_LKRG_MARKER2
#endif

};


void p_init_page_attr(void) {

   unsigned long *p_long_tmp = 0x0;
#if !defined(CONFIG_ARM)
   unsigned long p_long_offset = PAGE_SIZE/sizeof(p_long_tmp); // By purpose sizeof pointer
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_init_page_attr>\n");

   p_long_tmp = (unsigned long *)P_CTRL_ADDR;

#if !defined(CONFIG_ARM)
   if (*(p_long_tmp-p_long_offset) == P_LKRG_MARKER1) {
      p_print_log(P_LKRG_INFO, "Found marker before configuration page.\n");
      if (*(p_long_tmp+p_long_offset) == P_LKRG_MARKER1) {
         p_print_log(P_LKRG_INFO, "Found marker after configuration page.\n");
#endif
         p_set_memory_ro((unsigned long)p_long_tmp,1);
         p_print_log(P_LKRG_INFO, "Configuration page mark as RO.\n");
         p_attr_init++;
#if !defined(CONFIG_ARM)
         p_set_memory_np((unsigned long)(p_long_tmp-p_long_offset),1);
         p_print_log(P_LKRG_INFO, "Set-up GUARD page before configuration.\n");
         if (*(p_long_tmp+p_long_offset*2) == P_LKRG_MARKER2) {
            p_print_log(P_LKRG_INFO, "Found next marker after configuration page.\n");
            p_set_memory_np((unsigned long)(p_long_tmp+p_long_offset),1);
            p_print_log(P_LKRG_INFO, "Set-up GUARD page after configuration.\n");
            p_attr_init++;
         }
#endif

#if !defined(CONFIG_ARM64)
         P_SYM(p_flush_tlb_all)();
#else
         flush_tlb_all();
#endif

#if !defined(CONFIG_ARM)
      }
   } else {
      p_print_log(P_LKRG_CRIT,
             "ERROR: Can't find marker pages so configuration page is NOT RO :( Continue...\n");
      p_print_log(P_LKRG_INFO, "*(p_long_tmp[0x%lx]-PAGE_SIZE) => [0x%lx] 0x%lx\n",
                  (unsigned long)p_long_tmp,
                  (unsigned long)p_long_tmp-p_long_offset,
                  *(p_long_tmp-p_long_offset));
      p_print_log(P_LKRG_INFO, "*(p_long_tmp[0x%lx]+PAGE_SIZE) => [0x%lx] 0x%lx\n",
                  (unsigned long)p_long_tmp,
                  (unsigned long)p_long_tmp+p_long_offset,
                  *(p_long_tmp+p_long_offset));
      p_print_log(P_LKRG_INFO, "*(p_long_tmp[0x%lx]+2*PAGE_SIZE) => [0x%lx] 0x%lx\n",
                  (unsigned long)p_long_tmp,
                  (unsigned long)p_long_tmp+2*p_long_offset,
                  *(p_long_tmp+2*p_long_offset));
      p_print_log(P_LKRG_INFO, "*(p_long_tmp[0x%lx]+3*PAGE_SIZE) => [0x%lx] 0x%lx\n",
                  (unsigned long)p_long_tmp,
                  (unsigned long)p_long_tmp+3*p_long_offset,
                  *(p_long_tmp+3*p_long_offset));
   }
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_init_page_attr>\n");

}

void p_uninit_page_attr(void) {

   unsigned long *p_long_tmp = 0x0;
#if !defined(CONFIG_ARM)
   unsigned long p_long_offset = PAGE_SIZE/sizeof(p_long_tmp); // By purpose sizeof pointer
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_uninit_page_attr>\n");

   if (p_attr_init) {
      p_long_tmp = (unsigned long *)P_CTRL_ADDR;
      p_set_memory_rw((unsigned long)p_long_tmp,1);
      p_print_log(P_LKRG_INFO, "Configuration page marked to be RW again.\n");
#if !defined(CONFIG_ARM)
      p_set_memory_p((unsigned long)(p_long_tmp-p_long_offset),1);
      p_print_log(P_LKRG_INFO, "GUARD page before configuration marked to be PRESENT again.\n");
      p_set_memory_rw((unsigned long)(p_long_tmp-p_long_offset),1);
      *(p_long_tmp-p_long_offset) = P_LKRG_MARKER1;
      if (p_attr_init > 1) {
         p_print_log(P_LKRG_INFO, "GUARD page after configuration marked to be PRESENT again.\n");
         p_set_memory_p((unsigned long)(p_long_tmp+p_long_offset),1);
         p_set_memory_rw((unsigned long)(p_long_tmp+p_long_offset),1);
         *(p_long_tmp+p_long_offset) = P_LKRG_MARKER1;
      }
#endif

#if !defined(CONFIG_ARM64)
      P_SYM(p_flush_tlb_all)();
#else
      flush_tlb_all();
#endif
      schedule();
   } else {
      p_print_log(P_LKRG_INFO, "Configuration page was NOT RO.\n");
   }

   p_attr_init ^= p_attr_init;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_uninit_page_attr>\n");

}

/*
 * Main entry point for the module - initialization.
 */
static int __init p_lkrg_register(void) {

   int p_ret = P_LKRG_SUCCESS;
   char p_cpu = 0x0;
   char p_freeze = 0x0;

   p_print_log(P_LKRG_CRIT, "Loading LKRG...\n");

   /*
    * Generate random SipHash key
    */
   p_global_siphash_key.p_low  = (uint64_t)get_random_long();
   p_global_siphash_key.p_high = (uint64_t)get_random_long();

   if (p_init_log_level >= P_LOG_LEVEL_MAX)
      P_CTRL(p_log_level) = P_LOG_LEVEL_MAX-1;      // Max
   else
      P_CTRL(p_log_level) = p_init_log_level;

   if (get_kallsyms_address() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
             "Can't find kallsyms_lookup_name() function address! Exiting...\n");
      return P_LKRG_RESOLVER_ERROR;
   }
#ifdef P_LKRG_DEBUG
     else {
        p_print_log(P_LKRG_DBG,
               "kallsyms_lookup_name() => 0x%lx\n",(unsigned long)P_SYM(p_kallsyms_lookup_name));
     }
#endif

   P_SYM(p_freeze_processes) = (int (*)(void))P_SYM(p_kallsyms_lookup_name)("freeze_processes");

   if (!P_SYM(p_freeze_processes)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'freeze_processes' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   P_SYM(p_thaw_processes) = (void (*)(void))P_SYM(p_kallsyms_lookup_name)("thaw_processes");

   if (!P_SYM(p_thaw_processes)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'thaw_processes' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   // Freeze all non-kernel processes
   while (P_SYM(p_freeze_processes)())
      schedule();

   p_freeze = 0x1;

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

#if !defined(CONFIG_ARM64)

   P_SYM(p_flush_tlb_all) = (void (*)(void))P_SYM(p_kallsyms_lookup_name)("flush_tlb_all");

   if (!P_SYM(p_flush_tlb_all)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'flush_tlb_all' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

#endif


#if defined(CONFIG_X86)

   P_SYM(p_change_page_attr_set_clr) =
          (int (*)(unsigned long *, int, pgprot_t, pgprot_t, int, int, struct page **))
          P_SYM(p_kallsyms_lookup_name)("change_page_attr_set_clr");

   if (!P_SYM(p_change_page_attr_set_clr)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'change_page_attr_set_clr' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)

   P_SYM(p_change_memory_common) =
          (int (*)(unsigned long, int, pgprot_t, pgprot_t))
          P_SYM(p_kallsyms_lookup_name)("change_memory_common");

   if (!P_SYM(p_change_memory_common)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'change_memory_common' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

#else

   p_print_log(P_LKRG_CRIT, "UNSUPPORTED PLATFORM! Exiting...\n");
   p_ret = P_LKRG_GENERAL_ERROR;
   goto p_main_error;

#endif

   if (p_register_comm_channel()) {
      p_print_log(P_LKRG_CRIT,
             "Can't initialize communication channel (sysctl) :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

#if defined(CONFIG_X86)
   if (P_IS_SMEP_ENABLED(p_pcfi_CPU_flags)) {
      P_CTRL(p_smep_panic) = 0x1;
   } else {
      p_print_log(P_LKRG_ERR,
             "System does NOT support SMEP. LKRG can't enforece smep_panic :(\n");
   }
#endif

   if (P_CTRL(p_hide_module)) {
      p_hide_itself();
   }

   p_integrity_timer();
   p_register_notifiers();
   P_CTRL(p_random_events) = 0x1;
   p_init_page_attr();

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
      p_unregister_arch_metadata();
      p_offload_cache_delete();
      p_deregister_module_notifier();
      if (p_db.p_CPU_metadata_array) {
         kzfree(p_db.p_CPU_metadata_array);
         p_db.p_CPU_metadata_array = NULL;
      }
      p_uninit_page_attr();
   }

   if (p_freeze) {
      // Thaw all non-kernel processes
      P_SYM(p_thaw_processes)();
      p_freeze = 0x0;
   }

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

   p_uninit_page_attr();

   // Freeze all non-kernel processes
   while (P_SYM(p_freeze_processes)())
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
   p_offload_cache_delete();
   p_unregister_arch_metadata();
   p_deregister_module_notifier();


   if (p_db.p_CPU_metadata_array)
      kzfree(p_db.p_CPU_metadata_array);

   // Thaw all non-kernel processes
   P_SYM(p_thaw_processes)();

   p_print_log(P_LKRG_CRIT, "LKRG unloaded!\n");
}


module_init(p_lkrg_register);
module_exit(p_lkrg_deregister);

module_param(p_init_log_level, uint, 0000);
MODULE_PARM_DESC(p_init_log_level, "Logging level init value [1 (alive) is default]");

MODULE_AUTHOR("Adam 'pi3' Zabrocki (http://pi3.com.pl)");
MODULE_DESCRIPTION("pi3's Linux kernel Runtime Guard");
MODULE_LICENSE("GPL v2");
