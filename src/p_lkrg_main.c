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

unsigned int log_level = 3;
unsigned int heartbeat = 0;
unsigned int block_modules = 0;
unsigned int interval = 15;
unsigned int kint_validate = 3;
unsigned int kint_enforce = 2;
unsigned int msr_validate = 0;
unsigned int pint_validate = 1;
unsigned int pint_enforce = 1;
unsigned int pcfi_validate = 2;
unsigned int pcfi_enforce = 1;
unsigned int umh_validate = 1;
unsigned int umh_enforce = 1;
#if defined(CONFIG_X86)
unsigned int smep_validate = 1;
unsigned int smep_enforce = 2;
unsigned int smap_validate = 1;
unsigned int smap_enforce = 2;
#endif
unsigned int profile_validate = 3;
unsigned int profile_enforce = 2;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
static enum cpuhp_state p_hot_cpus;
#endif
unsigned int p_attr_init = 0;

p_ro_page p_ro __p_lkrg_read_only = {

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   .p_marker_np1 = P_LKRG_MARKER1,
#endif

   .p_lkrg_global_ctrl.ctrl = {
      .p_kint_validate = 3,               // kint_validate
      .p_kint_enforce = 2,                // kint_enforce
      .p_pint_validate = 1,               // pint_validate
      .p_pint_enforce = 1,                // pint_enforce
      .p_interval = 15,                   // interval
      .p_log_level = 3,                   // log_level
      .p_trigger = 0,                     // trigger
      .p_block_modules = 0,               // block_modules
      .p_hide_lkrg = 0,                   // hide_lkrg
      .p_heartbeat = 0,                   // heartbeat
#if defined(CONFIG_X86)
      .p_smep_validate = 1,               // smep_validate
      .p_smep_enforce = 2,                // smep_enforce
      .p_smap_validate = 1,               // smap_validate
      .p_smap_enforce = 2,                // smap_enforce
#endif
      .p_umh_validate = 1,                // umh_validate
      .p_umh_enforce = 1,                 // umh_enforce
      .p_msr_validate = 0,                // msr_validate
      .p_pcfi_validate = 2,               // pcfi_validate
      .p_pcfi_enforce = 1,                // pcfi_enforce
      /* Profiles */
      .p_profile_validate = 3,            // profile_validate
      .p_profile_enforce = 2              // profile_enforce
   },

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   .p_marker_np2 = P_LKRG_MARKER1,
   .p_marker_np3 = P_LKRG_MARKER2
#endif

};


static void p_init_page_attr(void) {

   unsigned long *p_long_tmp = 0;
#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   unsigned long p_long_offset = PAGE_SIZE/sizeof(p_long_tmp); // On purpose sizeof pointer
#endif

   p_long_tmp = (unsigned long *)P_CTRL_ADDR;

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   if (*(p_long_tmp-p_long_offset) == P_LKRG_MARKER1) {
      p_print_log(P_LKRG_INFO, "Found marker before configuration page.\n");
      if (*(p_long_tmp+p_long_offset) == P_LKRG_MARKER1) {
         p_print_log(P_LKRG_INFO, "Found marker after configuration page.\n");
#endif
         P_SYM(p_state_init) = 2;
         p_set_memory_ro((unsigned long)p_long_tmp,1);
         p_print_log(P_LKRG_INFO, "Configuration page marked read-only.\n");
         p_attr_init++;
#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
         p_set_memory_np((unsigned long)(p_long_tmp-p_long_offset),1);
         p_print_log(P_LKRG_INFO, "Setup guard page before configuration page.\n");
         if (*(p_long_tmp+p_long_offset*2) == P_LKRG_MARKER2) {
            p_print_log(P_LKRG_INFO, "Found next marker after configuration page.\n");
            p_set_memory_np((unsigned long)(p_long_tmp+p_long_offset),1);
            p_print_log(P_LKRG_INFO, "Setup guard page after configuration page.\n");
            p_attr_init++;
         }
#endif

#if !defined(CONFIG_ARM64)
         P_SYM(p_flush_tlb_all)();
#else
         flush_tlb_all();
#endif

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
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
}

static void p_uninit_page_attr(void) {

   unsigned long *p_long_tmp = 0;
#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   unsigned long p_long_offset = PAGE_SIZE/sizeof(p_long_tmp); // On purpose sizeof pointer
#endif

   if (p_attr_init) {
      p_long_tmp = (unsigned long *)P_CTRL_ADDR;
      p_set_memory_rw((unsigned long)p_long_tmp,1);
      p_print_log(P_LKRG_INFO, "Configuration page marked read-write.\n");
#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
      p_set_memory_p((unsigned long)(p_long_tmp-p_long_offset),1);
      p_print_log(P_LKRG_INFO, "Disabled guard page before configuration page.\n");
      p_set_memory_rw((unsigned long)(p_long_tmp-p_long_offset),1);
      *(p_long_tmp-p_long_offset) = P_LKRG_MARKER1;
      if (p_attr_init > 1) {
         p_print_log(P_LKRG_INFO, "Disabled guard page after configuration page.\n");
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
}

void p_parse_module_params(void) {

   /* Interval */
   if (interval > 1800) {
      P_CTRL(p_interval) = 1800;       // Max
   } else if (interval < 5) {
      P_CTRL(p_interval) = 5;          // Min
   } else {
      P_CTRL(p_interval) = interval;
   }

   /* log_level */
   if (log_level >= P_LOG_LEVEL_MAX) {
      P_CTRL(p_log_level) = P_LOG_LEVEL_MAX-1;      // Max
   } else {
      P_CTRL(p_log_level) = log_level;
   }

   /* heartbeat */
   if (heartbeat > 1) {
      P_CTRL(p_heartbeat) = 1;
   } else {
      P_CTRL(p_heartbeat) = heartbeat;
   }

   /* block_modules */
   if (block_modules > 1) {
      P_CTRL(p_block_modules) = 1;
   } else {
      P_CTRL(p_block_modules) = block_modules;
   }

   /* kint_validate */
   if (kint_validate > 3) {
      P_CTRL(p_kint_validate) = 3;
      P_CTRL(p_profile_validate) = 9;
   } else if (P_CTRL(p_kint_validate) != kint_validate) {
      P_CTRL(p_kint_validate) = kint_validate;
      P_CTRL(p_profile_validate) = 9;
   }

   /* kint_enforce */
   if (kint_enforce > 2) {
      P_CTRL(p_kint_enforce) = 2;
      P_CTRL(p_profile_enforce) = 9;
   } else if (P_CTRL(p_kint_enforce) != kint_enforce) {
      P_CTRL(p_kint_enforce) = kint_enforce;
      P_CTRL(p_profile_enforce) = 9;
   }

   /* msr_validate */
   if (msr_validate > 1) {
      P_CTRL(p_msr_validate) = 1;
      P_CTRL(p_profile_validate) = 9;
   } else if (P_CTRL(p_msr_validate) != msr_validate) {
      P_CTRL(p_msr_validate) = msr_validate;
      P_CTRL(p_profile_validate) = 9;
   }

   /* pint_validate */
   if (pint_validate > 3) {
      P_CTRL(p_pint_validate) = 3;
      P_CTRL(p_profile_validate) = 9;
   } else if (P_CTRL(p_pint_validate) != pint_validate) {
      P_CTRL(p_pint_validate) = pint_validate;
      P_CTRL(p_profile_validate) = 9;
   }

   /* pint_enforce */
   if (pint_enforce > 2) {
      P_CTRL(p_pint_enforce) = 2;
      P_CTRL(p_profile_enforce) = 9;
   } else if (P_CTRL(p_pint_enforce) != pint_enforce) {
      P_CTRL(p_pint_enforce) = pint_enforce;
      P_CTRL(p_profile_enforce) = 9;
   }

   /* umh_validate */
   if (umh_validate > 2) {
      P_CTRL(p_umh_validate) = 2;
      P_CTRL(p_profile_validate) = 9;
   } else if (P_CTRL(p_umh_validate) != umh_validate) {
      P_CTRL(p_umh_validate) = umh_validate;
      P_CTRL(p_profile_validate) = 9;
   }

   /* umh_enforce */
   if (umh_enforce > 2) {
      P_CTRL(p_umh_enforce) = 2;
      P_CTRL(p_profile_enforce) = 9;
   } else if (P_CTRL(p_umh_enforce) != umh_enforce) {
      P_CTRL(p_umh_enforce) = umh_enforce;
      P_CTRL(p_profile_enforce) = 9;
   }

   /* pcfi_validate */
   if (pcfi_validate > 2) {
      P_CTRL(p_pcfi_validate) = 2;
      P_CTRL(p_profile_validate) = 9;
   } else if (P_CTRL(p_pcfi_validate) != pcfi_validate) {
      P_CTRL(p_pcfi_validate) = pcfi_validate;
      P_CTRL(p_profile_validate) = 9;
   }

   /* pcfi_enforce */
   if (pcfi_enforce > 2) {
      P_CTRL(p_pcfi_enforce) = 2;
      P_CTRL(p_profile_enforce) = 9;
   } else if (P_CTRL(p_pcfi_enforce) != pcfi_enforce) {
      P_CTRL(p_pcfi_enforce) = pcfi_enforce;
      P_CTRL(p_profile_enforce) = 9;
   }

   p_pcfi_CPU_flags = 0;

#if defined(CONFIG_X86)

   if (boot_cpu_has(X86_FEATURE_SMEP)) {
      P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);

      /* smep_validate */
      if (smep_validate > 1) {
         P_CTRL(p_smep_validate) = 1;
         P_CTRL(p_profile_validate) = 9;
      } else if (P_CTRL(p_smep_validate) != smep_validate) {
         P_CTRL(p_smep_validate) = smep_validate;
         P_CTRL(p_profile_validate) = 9;
      }

      /* smep_enforce */
      if (smep_enforce > 2) {
         P_CTRL(p_smep_enforce) = 2;
         P_CTRL(p_profile_enforce) = 9;
      } else if (P_CTRL(p_smep_enforce) != smep_enforce) {
         P_CTRL(p_smep_enforce) = smep_enforce;
         P_CTRL(p_profile_enforce) = 9;
      }
   } else {
      P_CTRL(p_smep_validate) = 0;
      P_CTRL(p_smep_enforce) = 0;
      p_print_log(P_LKRG_ERR,
            "System does NOT support SMEP. LKRG can't enforce SMEP validation :(\n");
   }

   if (boot_cpu_has(X86_FEATURE_SMAP)) {
      P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);

      /* smap_validate */
      if (smap_validate > 1) {
         P_CTRL(p_smap_validate) = 1;
         P_CTRL(p_profile_validate) = 9;
      } else if (P_CTRL(p_smap_validate) != smap_validate) {
         P_CTRL(p_smap_validate) = smap_validate;
         P_CTRL(p_profile_validate) = 9;
      }

      /* smap_enforce */
      if (smap_enforce > 2) {
         P_CTRL(p_smap_enforce) = 2;
         P_CTRL(p_profile_enforce) = 9;
      } else if (P_CTRL(p_smap_enforce) != smap_enforce) {
         P_CTRL(p_smap_enforce) = smap_enforce;
         P_CTRL(p_profile_enforce) = 9;
      }
   } else {
      P_CTRL(p_smap_validate) = 0;
      P_CTRL(p_smap_enforce) = 0;
      p_print_log(P_LKRG_ERR,
            "System does NOT support SMAP. LKRG can't enforce SMAP validation :(\n");
   }

   P_ENABLE_WP_FLAG(p_pcfi_CPU_flags);

#endif

}

/*
 * Main entry point for the module - initialization.
 */
static int __init p_lkrg_register(void) {

   int p_ret = P_LKRG_SUCCESS;
   char p_cpu = 0;
   char p_freeze = 0;

   p_print_log(P_LKRG_CRIT, "Loading LKRG...\n");
   P_SYM(p_state_init) = 0;

   /*
    * Generate random SipHash key
    */
   p_global_siphash_key.p_low  = (uint64_t)get_random_long();
   p_global_siphash_key.p_high = (uint64_t)get_random_long();

   p_parse_module_params();
   P_SYM(p_find_me) = THIS_MODULE;

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

#if defined(CONFIG_X86)
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
   P_SYM(p_native_write_cr4) = (void (*)(unsigned long))P_SYM(p_kallsyms_lookup_name)("native_write_cr4");

   if (!P_SYM(p_native_write_cr4)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'native_write_cr4' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }
 #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
   P_SYM(p_module_address) = (struct module* (*)(unsigned long))P_SYM(p_kallsyms_lookup_name)("__module_address");

   if (!P_SYM(p_module_address)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find '__module_address' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   P_SYM(p_module_text_address) = (struct module* (*)(unsigned long))P_SYM(p_kallsyms_lookup_name)("__module_text_address");

   if (!P_SYM(p_module_text_address)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find '__module_text_address' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }
#endif

#if defined(CONFIG_OPTPROBES)
   P_SYM(p_wait_for_kprobe_optimizer) = (void (*)(void))P_SYM(p_kallsyms_lookup_name)("wait_for_kprobe_optimizer");

   if (!P_SYM(p_wait_for_kprobe_optimizer)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'wait_for_kprobe_optimizer' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }
#endif

   // Freeze all non-kernel processes
   while (P_SYM(p_freeze_processes)())
      schedule();

   p_freeze = 1;

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
   p_cpu = 1;

#if !defined(CONFIG_ARM64)

   P_SYM(p_flush_tlb_all) = (void (*)(void))P_SYM(p_kallsyms_lookup_name)("flush_tlb_all");

   if (!P_SYM(p_flush_tlb_all)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'flush_tlb_all' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

#endif


#if defined(P_KERNEL_AGGRESSIVE_INLINING)

   P_SYM(p_kernel_set_memory_ro) = (int (*)(unsigned long, int))
                            P_SYM(p_kallsyms_lookup_name)("set_memory_ro");
   if (!P_SYM(p_kernel_set_memory_ro)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'set_memory_ro' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   P_SYM(p_kernel_set_memory_rw) = (int (*)(unsigned long, int))
                            P_SYM(p_kallsyms_lookup_name)("set_memory_rw");
   if (!P_SYM(p_kernel_set_memory_rw)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'set_memory_rw' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

 #if defined(CONFIG_X86)
   ;
/*
   P_SYM(p_kernel_set_memory_np) = (int (*)(unsigned long, int))
                            P_SYM(p_kallsyms_lookup_name)("set_memory_np");
   if (!P_SYM(p_kernel_set_memory_np)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'set_memory_np' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }
*/
 #elif defined(CONFIG_ARM64)
   P_SYM(p_kernel_set_memory_valid) = (int (*)(unsigned long, int, int))
                               P_SYM(p_kallsyms_lookup_name)("set_memory_valid");
   if (!P_SYM(p_kernel_set_memory_valid)) {
      p_print_log(P_LKRG_ERR,
             "ERROR: Can't find 'set_memory_valid' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }
 #endif

#else
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
#endif

   if (p_register_comm_channel()) {
      p_print_log(P_LKRG_CRIT,
             "Can't initialize communication channel (sysctl) :(\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_main_error;
   }

   if (P_CTRL(p_hide_lkrg)) {
      p_hide_itself();
   }

   p_integrity_timer();
   p_register_notifiers();
   p_init_page_attr();

   p_print_log(P_LKRG_CRIT,
          "LKRG initialized successfully!\n");

   p_ret = P_LKRG_SUCCESS;

p_main_error:

   if (p_ret != P_LKRG_SUCCESS) {
      P_CTRL(p_kint_validate) = 0;
      p_deregister_notifiers();
      if (p_timer.function)
         del_timer_sync(&p_timer);
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
         p_kzfree(p_db.p_CPU_metadata_array);
         p_db.p_CPU_metadata_array = NULL;
      }
      p_uninit_page_attr();
#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
      if (p_db.kernel_stext_copy)
         vfree(p_db.kernel_stext_copy);
#endif
   }

   if (p_freeze) {
      // Thaw all non-kernel processes
      P_SYM(p_thaw_processes)();
      p_freeze = 0;
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

   P_CTRL(p_kint_validate) = 0;
   p_deregister_notifiers();
   if (p_timer.function)
      del_timer_sync(&p_timer);


   // Freeze all non-kernel processes
   while (P_SYM(p_freeze_processes)())
      schedule();

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
   p_unregister_arch_metadata();
   p_offload_cache_delete();
   p_deregister_module_notifier();


   if (p_db.p_CPU_metadata_array)
      p_kzfree(p_db.p_CPU_metadata_array);

#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
   if (p_db.kernel_stext_copy)
      vfree(p_db.kernel_stext_copy);
#endif

   // Thaw all non-kernel processes
   P_SYM(p_thaw_processes)();

   p_print_log(P_LKRG_CRIT, "LKRG unloaded!\n");
}


#ifdef MODULE
module_init(p_lkrg_register);
#else
late_initcall_sync(p_lkrg_register);
#endif
module_exit(p_lkrg_deregister);

module_param(log_level, uint, 0000);
MODULE_PARM_DESC(log_level, "log_level [3 (warn) is default]");
module_param(heartbeat, uint, 0000);
MODULE_PARM_DESC(heartbeat, "heartbeat [0 (don't print) is default]");
module_param(block_modules, uint, 0000);
MODULE_PARM_DESC(block_modules, "block_modules [0 (don't block) is default]");
module_param(interval, uint, 0000);
MODULE_PARM_DESC(interval, "interval [15 seconds is default]");
module_param(kint_validate, uint, 0000);
MODULE_PARM_DESC(kint_validate, "kint_validate [3 (periodically + random events) is default]");
module_param(kint_enforce, uint, 0000);
MODULE_PARM_DESC(kint_enforce, "kint_enforce [2 (panic) is default]");
module_param(msr_validate, uint, 0000);
MODULE_PARM_DESC(msr_validate, "msr_validate [0 (disabled) is default]");
module_param(pint_validate, uint, 0000);
MODULE_PARM_DESC(pint_validate, "pint_validate [1 (current) is default]");
module_param(pint_enforce, uint, 0000);
MODULE_PARM_DESC(pint_enforce, "pint_enforce [1 (kill task) is default]");
module_param(umh_validate, uint, 0000);
MODULE_PARM_DESC(umh_validate, "umh_validate [1 (allow specific paths) is default]");
module_param(umh_enforce, uint, 0000);
MODULE_PARM_DESC(umh_enforce, "umh_enforce [1 (prevent execution) is default]");
module_param(pcfi_validate, uint, 0000);
MODULE_PARM_DESC(pcfi_validate, "pcfi_validate [2 (fully enabled pCFI) is default]");
module_param(pcfi_enforce, uint, 0000);
MODULE_PARM_DESC(pcfi_enforce, "pcfi_enforce [1 (kill task) is default]");
#if defined(CONFIG_X86)
module_param(smep_validate, uint, 0000);
MODULE_PARM_DESC(smep_validate, "smep_validate [1 (enabled) is default]");
module_param(smep_enforce, uint, 0000);
MODULE_PARM_DESC(smep_enforce, "smep_enforce [2 (panic) is default]");
module_param(smap_validate, uint, 0000);
MODULE_PARM_DESC(smap_validate, "smap_validate [1 (enabled) is default]");
module_param(smap_enforce, uint, 0000);
MODULE_PARM_DESC(smap_enforce, "smap_enforce [2 (panic) is default]");
#endif

MODULE_AUTHOR("Adam 'pi3' Zabrocki (http://pi3.com.pl)");
MODULE_DESCRIPTION("pi3's Linux kernel Runtime Guard");
MODULE_LICENSE("GPL v2");
