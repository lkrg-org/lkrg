/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Communication channel - sysctl interface
 *
 * Notes:
 *  - Allow administrator of the system to interact with LKRG via sysctl interface
 *
 * Timeline:
 *  - Created: 26.X.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"


static struct ctl_table_header *p_sysctl_handle;

static int p_timestamp_min = 0x5;
static int p_timestamp_max = 0x708; // 1800

static int p_log_level_min = P_LOG_LEVEL_NONE;
static int p_log_level_max = P_LOG_LEVEL_MAX - 1;

static int p_block_module_min = 0x0;
static int p_block_module_max = 0x1;

static int p_force_run_min = 0x0;
static int p_force_run_max = 0x1;

#ifdef P_LKRG_UNHIDE
static int p_hide_module_min = 0x0;
static int p_hide_module_max = 0x1;
#endif

static int p_clean_message_min = 0x0;
static int p_clean_message_max = 0x1;

static int p_random_events_min = 0x0;
static int p_random_events_max = 0x1;

static int p_ci_panic_min = 0x0;
static int p_ci_panic_max = 0x1;

#ifdef CONFIG_X86
static int p_smep_panic_min = 0x0;
static int p_smep_panic_max = 0x1;
#endif

static int p_enforce_umh_min = 0x0;
static int p_enforce_umh_max = 0x2;

/* Enforce MSR validation */
static int p_enforce_msr_min = 0x0;
static int p_enforce_msr_max = 0x1;

/* Enforce pCFI validation */
static int p_enforce_pcfi_min = 0x0;
static int p_enforce_pcfi_max = 0x2;

static int p_sysctl_timestamp(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_block_modules(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_log_level(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_force_run(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#ifdef P_LKRG_UNHIDE
static int p_sysctl_hide(struct ctl_table *p_table, int p_write,
                         void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_clean_message(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_random_events(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_ci_panic(struct ctl_table *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#ifdef CONFIG_X86
static int p_sysctl_smep_panic(struct ctl_table *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_enforce_umh(struct ctl_table *p_table, int p_write,
                                void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_enforce_msr(struct ctl_table *p_table, int p_write,
                                void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_enforce_pcfi(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);


struct ctl_table p_lkrg_sysctl_base[] = {
   {
      .procname    = "lkrg",
      .mode        = 0600,
      .child       = p_lkrg_sysctl_table,
   },
   { }
};

struct ctl_table p_lkrg_sysctl_table[] = {
   {
      .procname       = "timestamp",
      .data           = &P_CTRL(p_timestamp),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_timestamp,
      .extra1         = &p_timestamp_min,
      .extra2         = &p_timestamp_max,
   },
   {
      .procname       = "block_modules",
      .data           = &P_CTRL(p_block_modules),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_block_modules,
      .extra1         = &p_block_module_min,
      .extra2         = &p_block_module_max,
   },
   {
      .procname       = "log_level",
      .data           = &P_CTRL(p_log_level),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
//      .proc_handler   = proc_dointvec_minmax,
      .proc_handler   = p_sysctl_log_level,
      .extra1         = &p_log_level_min,
      .extra2         = &p_log_level_max,
   },
   {
      .procname       = "force_run",
      .data           = &P_CTRL(p_force_run),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_force_run,
      .extra1         = &p_force_run_min,
      .extra2         = &p_force_run_max,
   },
#ifdef P_LKRG_UNHIDE
   {
      .procname       = "hide",
      .data           = &P_CTRL(p_hide_module),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_hide,
      .extra1         = &p_hide_module_min,
      .extra2         = &p_hide_module_max,
   },
#endif
   {
      .procname       = "clean_message",
      .data           = &P_CTRL(p_clean_message),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_clean_message,
      .extra1         = &p_clean_message_min,
      .extra2         = &p_clean_message_max,
   },
   {
      .procname       = "random_events",
      .data           = &P_CTRL(p_random_events),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_random_events,
      .extra1         = &p_random_events_min,
      .extra2         = &p_random_events_max,
   },
   {
      .procname       = "ci_panic",
      .data           = &P_CTRL(p_ci_panic),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_ci_panic,
      .extra1         = &p_ci_panic_min,
      .extra2         = &p_ci_panic_max,
   },
#ifdef CONFIG_X86
   {
      .procname       = "smep_panic",
      .data           = &P_CTRL(p_smep_panic),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smep_panic,
      .extra1         = &p_smep_panic_min,
      .extra2         = &p_smep_panic_max,
   },
#endif
   {
      .procname       = "enforce_umh",
      .data           = &P_CTRL(p_enforce_umh),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_enforce_umh,
      .extra1         = &p_enforce_umh_min,
      .extra2         = &p_enforce_umh_max,
   },
   {
      .procname       = "enforce_msr",
      .data           = &P_CTRL(p_enforce_msr),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_enforce_msr,
      .extra1         = &p_enforce_msr_min,
      .extra2         = &p_enforce_msr_max,
   },
   {
      .procname       = "enforce_pcfi",
      .data           = &P_CTRL(p_enforce_pcfi),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_enforce_pcfi,
      .extra1         = &p_enforce_pcfi_min,
      .extra2         = &p_enforce_pcfi_max,
   },
   { }
};


static int p_sysctl_timestamp(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {
   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_timestamp>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      p_print_log(P_LKRG_CRIT, "[CI] New timestamp => %d\n",P_CTRL(p_timestamp));
      p_offload_work(0); // run integrity check!
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_timestamp>\n");

   return p_ret;
}

static int p_sysctl_block_modules(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_block_modules>\n");

   p_tmp = P_CTRL(p_block_modules);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_block_modules) && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling \"blocking modules\" feature.\n");
      } else if (p_tmp && !P_CTRL(p_clean_message)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling \"blocking modules\" feature.\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_block_modules>\n");

   return p_ret;
}

static int p_sysctl_log_level(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {
   int p_ret;
   char *p_log_level_string[] = { "NONE",
                                  "ALIVE",
                                  "ERROR",
                                  "WARN",
                                  "INFO"
#if defined(P_LKRG_DEBUG)
                                  ,"DEBUG",
                                  "STRONG_DEBUG"
#endif
                                };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_log_level>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      p_print_log(P_LKRG_CRIT, "New log level => %d (%s)\n",
                  P_CTRL(p_log_level),
                  p_log_level_string[P_CTRL(p_log_level]));
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_log_level>\n");

   return p_ret;
}


static int p_sysctl_force_run(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_force_run>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_force_run)) {
         p_offload_work(0); // run integrity check!
         P_CTRL(p_force_run) = 0x0; // Restore 0 value - user only sees that value!
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_force_run>\n");

   return p_ret;
}

#ifdef P_LKRG_UNHIDE
static int p_sysctl_hide(struct ctl_table *p_table, int p_write,
                         void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_hide>\n");

   p_tmp = P_CTRL(p_hide_module);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_hide_module)) {
         P_CTRL(p_hide_module) = p_tmp; // Restore previous state - for sync
         p_hide_itself(); // hide module!
      } else {
         P_CTRL(p_hide_module) = p_tmp; // Restore previous state - for sync
         p_unhide_itself(); // Unide module!
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_hide>\n");

   return p_ret;
}
#endif

static int p_sysctl_clean_message(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_clean_message>\n");

   p_tmp = P_CTRL(p_clean_message);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_clean_message) && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling \"clean\" message.\n");
      } else if (p_tmp && !P_CTRL(p_clean_message)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling \"clean\" message.\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_clean_message>\n");

   return p_ret;
}

static int p_sysctl_random_events(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_random_events>\n");

   p_tmp = P_CTRL(p_random_events);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_random_events) && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling LKRG verification on the random events in the system.\n");
         p_register_notifiers();
      } else if (p_tmp && !P_CTRL(p_random_events)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling LKRG verification on the random events in the system.\n");
         p_deregister_notifiers();
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_random_events>\n");

   return p_ret;
}

static int p_sysctl_ci_panic(struct ctl_table *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_ci_panic>\n");

   p_tmp = P_CTRL(p_ci_panic);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_ci_panic) && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling kernel panic on LKRG's CI verification failure.\n");
      } else if (p_tmp && !P_CTRL(p_ci_panic)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling kernel panic on LKRG's CI verification failure.\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_ci_panic>\n");

   return p_ret;
}

#ifdef CONFIG_X86
static int p_sysctl_smep_panic(struct ctl_table *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_smep_panic>\n");

   p_tmp = P_CTRL(p_smep_panic);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smep_panic) && !p_tmp) {
         if (P_IS_SMEP_ENABLED(p_pcfi_CPU_flags)) {
            p_print_log(P_LKRG_CRIT,
                        "Enabling kernel panic on LKRG's SMEP verification failure.\n");
         } else {
            P_CTRL(p_smep_panic) = 0x0;
            p_print_log(P_LKRG_CRIT,
                        "System does NOT support SMEP. LKRG can't enable/disable smep_panic :(\n");
         }

      } else if (p_tmp && !P_CTRL(p_smep_panic)) {
         if (P_IS_SMEP_ENABLED(p_pcfi_CPU_flags)) {
            p_print_log(P_LKRG_CRIT,
                        "Disabling kernel panic on LKRG's SMEP verification failure.\n");
         } else {
            P_CTRL(p_smep_panic) = 0x0;
            p_print_log(P_LKRG_CRIT,
                        "System does NOT support SMEP. LKRG can't enable/disable smep_panic :(\n");
         }
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_smep_panic>\n");

   return p_ret;
}
#endif

static int p_sysctl_enforce_umh(struct ctl_table *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   char *p_umh_strings[] = { "Disable protection",
                             "Whitelist UMH paths",
                             "Completely block UMH" };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_enforce_umh>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      p_print_log(P_LKRG_CRIT, "[ED] New UMH configuration => %d (%s)\n",
                  P_CTRL(p_enforce_umh),
                  p_umh_strings[P_CTRL(p_enforce_umh)]);
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_enforce_umh>\n");

   return p_ret;
}

static int p_sysctl_enforce_msr(struct ctl_table *p_table, int p_write,
                                void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   int p_cpu;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_enforce_msr>\n");

   p_tmp = P_CTRL(p_enforce_msr);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_enforce_msr) && !p_tmp) {
         p_offload_work(0); // run integrity check!
         schedule();
         spin_lock(&p_db_lock);
         memset(p_db.p_CPU_metadata_array,0x0,sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids);
         for_each_present_cpu(p_cpu) {
            if (cpu_online(p_cpu)) {
                  smp_call_function_single(p_cpu,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
            }
         }
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
         spin_unlock(&p_db_lock);
         p_print_log(P_LKRG_CRIT,
                     "Enabling MSRs verification during CI.\n");
      } else if (p_tmp && !P_CTRL(p_enforce_msr)) {
         p_offload_work(0); // run integrity check!
         schedule();
         spin_lock(&p_db_lock);
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
         spin_unlock(&p_db_lock);
         p_print_log(P_LKRG_CRIT,
                     "Disabling MSRs verification during CI.\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_enforce_msr>\n");

   return p_ret;
}

static int p_sysctl_enforce_pcfi(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   char *p_pcfi_strings[] = { "Disabled",
                              "No stackwalk (weak)",
                              "Fully enabled" };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_enforce_pcfi>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      p_print_log(P_LKRG_CRIT, "[ED] New pCFI configuration => %d (%s)\n",
                  P_CTRL(p_enforce_pcfi),
                  p_pcfi_strings[P_CTRL(p_enforce_pcfi)]);
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_enforce_pcfi>\n");

   return p_ret;
}

int p_register_comm_channel(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_register_comm_channel>\n");

   if ( (p_sysctl_handle = register_sysctl_table(p_lkrg_sysctl_base)) == NULL) {
      p_print_log(P_LKRG_ERR,
             "Communication channel error! Can't register 'sysctl' table :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_register_comm_channel_out;
   }


p_register_comm_channel_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_register_comm_channel>\n");

   return p_ret;
}

void p_deregister_comm_channel(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_deregister_comm_channel>\n");

   unregister_sysctl_table(p_sysctl_handle);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_deregister_comm_channel>\n");

}
