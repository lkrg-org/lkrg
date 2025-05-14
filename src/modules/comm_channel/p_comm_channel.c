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

static int p_kint_validate_min = 0;
static int p_kint_validate_max = 3;

static int p_kint_enforce_min = 0;
static int p_kint_enforce_max = 2;

static int p_pint_validate_min = 0;
static int p_pint_validate_max = 3;

static int p_pint_enforce_min = 0;
static int p_pint_enforce_max = 2;

static int p_interval_min = 5;
static int p_interval_max = 1800;

static int p_log_level_min = P_LOG_MIN;
static int p_log_level_max = P_LOG_MAX;
static unsigned int p_log_level_new;

static int p_block_module_min = 0;
static int p_block_module_max = 1;

static int p_trigger_min = 0;
static int p_trigger_max = 1;

#ifdef LKRG_WITH_HIDE
static int p_hide_lkrg_min = 0;
static int p_hide_lkrg_max = 1;
#endif

static int p_heartbeat_min = 0;
static int p_heartbeat_max = 1;

#if defined(CONFIG_X86)
static int p_smep_validate_min = 0;
static int p_smep_validate_max = 1;

static int p_smep_enforce_min = 0;
static int p_smep_enforce_max = 2;

static int p_smap_validate_min = 0;
static int p_smap_validate_max = 1;

static int p_smap_enforce_min = 0;
static int p_smap_enforce_max = 2;
#endif

static int p_umh_validate_min = 0;
static int p_umh_validate_max = 2;

static int p_umh_enforce_min = 0;
static int p_umh_enforce_max = 2;

static int p_msr_validate_min = 0;
static int p_msr_validate_max = 1;

static int p_pcfi_validate_min = 0;
static int p_pcfi_validate_max = 2;

static int p_pcfi_enforce_min = 0;
static int p_pcfi_enforce_max = 2;

/* Profiles */
static int p_profile_validate_min = 0;
static int p_profile_validate_max = 9;

static int p_profile_enforce_min = 0;
static int p_profile_enforce_max = 9;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,11,0)
#define P_STRUCT_CTL_TABLE const struct ctl_table
#else
#define P_STRUCT_CTL_TABLE struct ctl_table
#endif

static int p_sysctl_kint_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_kint_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pint_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pint_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_interval(P_STRUCT_CTL_TABLE *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_block_modules(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_log_level(P_STRUCT_CTL_TABLE *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_trigger(P_STRUCT_CTL_TABLE *p_table, int p_write,
                            void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#ifdef LKRG_WITH_HIDE
static int p_sysctl_hide(P_STRUCT_CTL_TABLE *p_table, int p_write,
                         void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_heartbeat(P_STRUCT_CTL_TABLE *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#if defined(CONFIG_X86)
static int p_sysctl_smep_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_smep_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_smap_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_smap_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_umh_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_umh_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_msr_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pcfi_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pcfi_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_profile_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                     void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_profile_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                    void __user *p_buffer, size_t *p_len, loff_t *p_pos);


struct ctl_table p_lkrg_sysctl_table[] = {
   {
      .procname       = "kint_validate",
      .data           = &P_CTRL(p_kint_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_kint_validate,
      .extra1         = &p_kint_validate_min,
      .extra2         = &p_kint_validate_max,
   },
   {
      .procname       = "kint_enforce",
      .data           = &P_CTRL(p_kint_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_kint_enforce,
      .extra1         = &p_kint_enforce_min,
      .extra2         = &p_kint_enforce_max,
   },
   {
      .procname       = "pint_validate",
      .data           = &P_CTRL(p_pint_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_pint_validate,
      .extra1         = &p_pint_validate_min,
      .extra2         = &p_pint_validate_max,
   },
   {
      .procname       = "pint_enforce",
      .data           = &P_CTRL(p_pint_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_pint_enforce,
      .extra1         = &p_pint_enforce_min,
      .extra2         = &p_pint_enforce_max,
   },
   {
      .procname       = "interval",
      .data           = &P_CTRL(p_interval),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_interval,
      .extra1         = &p_interval_min,
      .extra2         = &p_interval_max,
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
      .data           = &p_log_level_new,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_log_level,
      .extra1         = &p_log_level_min,
      .extra2         = &p_log_level_max,
   },
   {
      .procname       = "trigger",
      .data           = &P_CTRL(p_trigger),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_trigger,
      .extra1         = &p_trigger_min,
      .extra2         = &p_trigger_max,
   },
#ifdef LKRG_WITH_HIDE
   {
      .procname       = "hide",
      .data           = &P_CTRL(p_hide_lkrg),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_hide,
      .extra1         = &p_hide_lkrg_min,
      .extra2         = &p_hide_lkrg_max,
   },
#endif
   {
      .procname       = "heartbeat",
      .data           = &P_CTRL(p_heartbeat),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_heartbeat,
      .extra1         = &p_heartbeat_min,
      .extra2         = &p_heartbeat_max,
   },
#if defined(CONFIG_X86)
   {
      .procname       = "smep_validate",
      .data           = &P_CTRL(p_smep_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smep_validate,
      .extra1         = &p_smep_validate_min,
      .extra2         = &p_smep_validate_max,
   },
   {
      .procname       = "smep_enforce",
      .data           = &P_CTRL(p_smep_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smep_enforce,
      .extra1         = &p_smep_enforce_min,
      .extra2         = &p_smep_enforce_max,
   },
   {
      .procname       = "smap_validate",
      .data           = &P_CTRL(p_smap_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smap_validate,
      .extra1         = &p_smap_validate_min,
      .extra2         = &p_smap_validate_max,
   },
   {
      .procname       = "smap_enforce",
      .data           = &P_CTRL(p_smap_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smap_enforce,
      .extra1         = &p_smap_enforce_min,
      .extra2         = &p_smap_enforce_max,
   },
#endif
   {
      .procname       = "umh_validate",
      .data           = &P_CTRL(p_umh_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_umh_validate,
      .extra1         = &p_umh_validate_min,
      .extra2         = &p_umh_validate_max,
   },
   {
      .procname       = "umh_enforce",
      .data           = &P_CTRL(p_umh_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_umh_enforce,
      .extra1         = &p_umh_enforce_min,
      .extra2         = &p_umh_enforce_max,
   },
   {
      .procname       = "msr_validate",
      .data           = &P_CTRL(p_msr_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_msr_validate,
      .extra1         = &p_msr_validate_min,
      .extra2         = &p_msr_validate_max,
   },
   {
      .procname       = "pcfi_validate",
      .data           = &P_CTRL(p_pcfi_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_pcfi_validate,
      .extra1         = &p_pcfi_validate_min,
      .extra2         = &p_pcfi_validate_max,
   },
   {
      .procname       = "pcfi_enforce",
      .data           = &P_CTRL(p_pcfi_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_pcfi_enforce,
      .extra1         = &p_pcfi_enforce_min,
      .extra2         = &p_pcfi_enforce_max,
   },
   {
      .procname       = "profile_validate",
      .data           = &P_CTRL(p_profile_validate),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_profile_validate,
      .extra1         = &p_profile_validate_min,
      .extra2         = &p_profile_validate_max,
   },
   {
      .procname       = "profile_enforce",
      .data           = &P_CTRL(p_profile_enforce),
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_profile_enforce,
      .extra1         = &p_profile_enforce_min,
      .extra2         = &p_profile_enforce_max,
   },
/*
 * Empty element at the end of array was required when register_sysctl() was a
 * function.  It's no longer required when it became a macro in 2023, and it's
 * disallowed after further changes in 2024 (starting with 6.11-rc kernels).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,11,0)
   { }
#endif
};


static int p_sysctl_kint_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "DISABLED",
      "MANUAL",
      "PERIODICALLY",
      "PERIODICALLY + RANDOM EVENTS"
   };

   p_tmp = P_CTRL(p_kint_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_kint_validate) != p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Changing 'kint_validate' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_kint_validate), p_str[P_CTRL(p_kint_validate)]);
         /* Random events */
         if (p_tmp < 3 && P_CTRL(p_kint_validate) == 3) {
            p_register_notifiers();
         } else if (p_tmp == 3 && P_CTRL(p_kint_validate) < 3) {
            p_deregister_notifiers();
         }
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_kint_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG & ACCEPT",
#if defined(CONFIG_X86)
      "LOG ONLY (For SELinux and CR0.WP LOG & RESTORE)",
#else
      "LOG ONLY (For SELinux LOG & RESTORE)",
#endif
      "PANIC"
   };

   p_tmp = P_CTRL(p_kint_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_kint_enforce) != p_tmp) {
         P_CTRL(p_profile_enforce) = 9;
         p_print_log(P_LOG_STATE, "Changing 'kint_enforce' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_kint_enforce), p_str[P_CTRL(p_kint_enforce)]);
#if defined(CONFIG_X86)
         if (P_CTRL(p_kint_enforce)) {
            P_ENABLE_WP_FLAG(p_pcfi_CPU_flags);
         }
#endif
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_pint_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "DISABLED",
      "CURRENT",
      "CURRENT",
      "ALL TASKS"
   };

   p_tmp = P_CTRL(p_pint_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pint_validate) != p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Changing 'pint_validate' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_pint_validate), p_str[P_CTRL(p_pint_validate)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_pint_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG & ACCEPT",
      "KILL TASK",
      "PANIC"
   };

   p_tmp = P_CTRL(p_pint_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pint_enforce) != p_tmp) {
         P_CTRL(p_profile_enforce) = 9;
         p_print_log(P_LOG_STATE, "Changing 'pint_enforce' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_pint_enforce), p_str[P_CTRL(p_pint_enforce)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}


static int p_sysctl_interval(P_STRUCT_CTL_TABLE *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {
   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_interval);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_interval) != p_tmp) {
         p_print_log(P_LOG_STATE, "Changing 'interval' from %d to %d", p_tmp, P_CTRL(p_interval));
         p_offload_work(0); // run integrity check!
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_block_modules(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_block_modules);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_block_modules) && !p_tmp) {
         p_print_log(P_LOG_STATE, "Enabling 'block_modules'");
      } else if (p_tmp && !P_CTRL(p_block_modules)) {
         p_print_log(P_LOG_STATE, "Disabling 'block_modules'");
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_log_level(P_STRUCT_CTL_TABLE *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {
   int p_ret;
   unsigned int p_log_level_old;
   static const char * const p_log_level_string[] = {
      "ALERT",
      "ALIVE",
      "FAULT",
      "ISSUE",
      "WATCH"
#if defined(P_LKRG_DEBUG)
      ,"DEBUG",
      "FLOOD"
#endif
   };

   p_log_level_new = p_log_level_old = P_CTRL(p_log_level);
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_log_level_new != p_log_level_old) {
         int increasing = p_log_level_new > p_log_level_old;
         p_lkrg_open_rw();
         if (increasing)
            P_CTRL(p_log_level) = p_log_level_new;
         p_print_log(P_LOG_STATE, "Changing 'log_level' from %d (%s) to %d (%s)",
                     p_log_level_old, p_log_level_string[p_log_level_old],
                     p_log_level_new, p_log_level_string[p_log_level_new]);
         if (!increasing)
            P_CTRL(p_log_level) = p_log_level_new;
         p_lkrg_close_rw();
      }
   }

   return p_ret;
}


static int p_sysctl_trigger(P_STRUCT_CTL_TABLE *p_table, int p_write,
                            void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_trigger)) {
         p_manual = 1;
         p_offload_work(0); // run integrity check!
         P_CTRL(p_trigger) = 0; // Restore 0 value - user only sees that value!
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

#ifdef LKRG_WITH_HIDE
static int p_sysctl_hide(P_STRUCT_CTL_TABLE *p_table, int p_write,
                         void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_hide_lkrg);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_hide_lkrg)) {
         P_CTRL(p_hide_lkrg) = p_tmp; // Restore previous state - for sync
         p_hide_itself(); // hide module!
      } else {
         P_CTRL(p_hide_lkrg) = p_tmp; // Restore previous state - for sync
         p_unhide_itself(); // Unhide the module!
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}
#endif

static int p_sysctl_heartbeat(P_STRUCT_CTL_TABLE *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_heartbeat);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_heartbeat) && !p_tmp) {
         p_print_log(P_LOG_STATE, "Enabling 'heartbeat'");
      } else if (p_tmp && !P_CTRL(p_heartbeat)) {
         p_print_log(P_LOG_STATE, "Disabling 'heartbeat'");
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

#if defined(CONFIG_X86)
static int p_sysctl_smep_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_smep_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smep_validate) && !p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         if (boot_cpu_has(X86_FEATURE_SMEP)) {
            p_print_log(P_LOG_STATE, "Enabling 'smep_validate'");
            P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
         } else {
/* FIXME: We had temporarily enabled P_CTRL(p_smep_validate) - is it safe? */
            P_CTRL(p_smep_validate) = 0;
            P_CTRL(p_smep_enforce) = 0;
            p_print_log(P_LOG_ISSUE, "System does not support SMEP, which won't be validated");
         }
      } else if (p_tmp && !P_CTRL(p_smep_validate)) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Disabling 'smep_validate'");
      }

   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_smep_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG & ACCEPT",
      "LOG & RESTORE",
      "PANIC"
   };

   p_tmp = P_CTRL(p_smep_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smep_enforce) != p_tmp) {
         P_CTRL(p_profile_enforce) = 9;
         if (boot_cpu_has(X86_FEATURE_SMEP)) {
            p_print_log(P_LOG_STATE, "Changing 'smep_enforce' from %d (%s) to %d (%s)",
                        p_tmp, p_str[p_tmp],
                        P_CTRL(p_smep_enforce), p_str[P_CTRL(p_smep_enforce)]);
            P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
         } else {
/* FIXME: We had temporarily enabled P_CTRL(p_smep_enforce) - is it safe? */
            P_CTRL(p_smep_enforce) = 0;
            P_CTRL(p_smep_validate) = 0;
            p_print_log(P_LOG_ISSUE, "System does not support SMEP, which won't be validated");
         }
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_smap_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

   p_tmp = P_CTRL(p_smap_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smap_validate) && !p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         if (boot_cpu_has(X86_FEATURE_SMAP)) {
            p_print_log(P_LOG_STATE, "Enabling 'smap_validate'");
            P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
         } else {
/* FIXME: We had temporarily enabled P_CTRL(p_smap_validate) - is it safe? */
            P_CTRL(p_smap_validate) = 0;
            P_CTRL(p_smap_enforce) = 0;
            p_print_log(P_LOG_ISSUE, "System does not support SMAP, which won't be validated");
         }
      } else if (p_tmp && !P_CTRL(p_smap_validate)) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Disabling 'smap_validate'");
      }

   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_smap_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG & ACCEPT",
      "LOG & RESTORE",
      "PANIC"
   };

   p_tmp = P_CTRL(p_smap_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smap_enforce) != p_tmp) {
         P_CTRL(p_profile_enforce) = 9;
         if (boot_cpu_has(X86_FEATURE_SMAP)) {
            p_print_log(P_LOG_STATE, "Changing 'smap_enforce' from %d (%s) to %d (%s)",
                        p_tmp, p_str[p_tmp],
                        P_CTRL(p_smap_enforce), p_str[P_CTRL(p_smap_enforce)]);
            P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
         } else {
/* FIXME: We had temporarily enabled P_CTRL(p_smap_enforce) - is it safe? */
            P_CTRL(p_smap_enforce) = 0;
            P_CTRL(p_smap_validate) = 0;
            p_print_log(P_LOG_ISSUE, "System does not support SMAP, which won't be validated");
         }
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}
#endif

static int p_sysctl_umh_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "Disable protection",
      "Allow specific paths",
      "Completely block usermodehelper"
   };

   p_tmp = P_CTRL(p_umh_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_umh_validate) != p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Changing 'umh_validate' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_umh_validate), p_str[P_CTRL(p_umh_validate)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_umh_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG ONLY",
      "PREVENT EXECUTION",
      "PANIC"
   };

   p_tmp = P_CTRL(p_umh_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_umh_enforce) != p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Changing 'umh_enforce' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_umh_enforce), p_str[P_CTRL(p_umh_enforce)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_msr_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   int p_cpu;
   unsigned int p_tmp;

   write_lock(&p_config_lock);
   p_tmp = P_CTRL(p_msr_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_msr_validate) && !p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Enabling 'msr_validate'");
         memset(p_db.p_CPU_metadata_array,0,sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids);
         for_each_present_cpu(p_cpu) {
            if (cpu_online(p_cpu)) {
                  smp_call_function_single(p_cpu,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
            }
         }
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
      } else if (p_tmp && !P_CTRL(p_msr_validate)) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Disabling 'msr_validate'");
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
      }
   }
   p_lkrg_close_rw();
   write_unlock(&p_config_lock);

   return p_ret;
}

static int p_sysctl_pcfi_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "Disabled",
      "No stackwalk (weak)",
      "Fully enabled"
   };

   p_tmp = P_CTRL(p_pcfi_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pcfi_validate) != p_tmp) {
         P_CTRL(p_profile_validate) = 9;
         p_print_log(P_LOG_STATE, "Changing 'pcfi_validate' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_pcfi_validate), p_str[P_CTRL(p_pcfi_validate)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_pcfi_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "LOG ONLY",
      "KILL TASK",
      "PANIC"
   };

   p_tmp = P_CTRL(p_pcfi_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pcfi_enforce) != p_tmp) {
         P_CTRL(p_profile_enforce) = 9;
         p_print_log(P_LOG_STATE, "Changing 'pcfi_enforce' from %d (%s) to %d (%s)",
                     p_tmp, p_str[p_tmp],
                     P_CTRL(p_pcfi_enforce), p_str[P_CTRL(p_pcfi_enforce)]);
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_profile_validate(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                     void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   int p_cpu;
   static const char * const p_str[] = {
      "Disabled",
      "Light",
      "Balanced",
      "Heavy",
      "Paranoid"
   };

   p_tmp = P_CTRL(p_profile_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_profile_validate) != p_tmp) {
         if (P_CTRL(p_profile_validate) > 4 && P_CTRL(p_profile_validate) != 9) {
            P_CTRL(p_profile_validate) = p_tmp;
            p_print_log(P_LOG_ISSUE, "Attempted to set 'profile_validate' to an unsupported value");
         } else {

            switch (P_CTRL(p_profile_validate)) {

               case 0:
                  /* kint_validate */
                  if (P_CTRL(p_kint_validate) == 3)
                     p_deregister_notifiers();
                  P_CTRL(p_kint_validate) = 0;  // Disabled
                  /* pint_validate */
                  P_CTRL(p_pint_validate) = 0;  // Disabled
                  /* pcfi_validate */
                  P_CTRL(p_pcfi_validate) = 0;  // Disabled
                  /* umh_validate */
                  P_CTRL(p_umh_validate) = 0;   // Disabled
                  /* msr_validate */
                  if (P_CTRL(p_msr_validate)) {
                     write_lock(&p_config_lock);
                     P_CTRL(p_msr_validate) = 0; // Disable
                     p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
                     write_unlock(&p_config_lock);
                  }
#if defined(CONFIG_X86)
                  /* smep_validate */
                  P_CTRL(p_smep_validate) = 0;
                  /* smap_validate */
                  P_CTRL(p_smap_validate) = 0;
#endif
                  break;

               case 1:
                  /* kint_validate */
                  if (P_CTRL(p_kint_validate) == 3)
                     p_deregister_notifiers();
                  P_CTRL(p_kint_validate) = 1;  // Manual trigger only
                  /* pint_validate */
                  P_CTRL(p_pint_validate) = 1;  // Current task only
                  /* pcfi_validate */
                  P_CTRL(p_pcfi_validate) = 1;  // Weak pCFI
                  /* umh_validate */
                  P_CTRL(p_umh_validate) = 1;   // Allow specific paths
                  /* msr_validate */
                  if (P_CTRL(p_msr_validate)) {
                     write_lock(&p_config_lock);
                     P_CTRL(p_msr_validate) = 0; // Disable
                     p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
                     write_unlock(&p_config_lock);
                  }
#if defined(CONFIG_X86)
                  /* smep_validate */
                  if (!P_CTRL(p_smep_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMEP)) {
                        P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smep_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smep_validate) = 0;
                        P_CTRL(p_smep_enforce) = 0;
                     }
                  }
                  /* smap_validate */
                  if (!P_CTRL(p_smap_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMAP)) {
                        P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smap_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smap_validate) = 0;
                        P_CTRL(p_smap_enforce) = 0;
                     }
                  }
#endif
                  break;

               case 2:
                  /* kint_validate */
                  if (P_CTRL(p_kint_validate) == 3)
                     p_deregister_notifiers();
                  P_CTRL(p_kint_validate) = 2;  // Timer
                  /* pint_validate */
                  P_CTRL(p_pint_validate) = 1;  // Current
                  /* pcfi_validate */
                  P_CTRL(p_pcfi_validate) = 1;  // Weak pCFI
                  /* umh_validate */
                  P_CTRL(p_umh_validate) = 1;   // Allow specific paths
                  /* msr_validate */
                  if (P_CTRL(p_msr_validate)) {
                     write_lock(&p_config_lock);
                     P_CTRL(p_msr_validate) = 0; // Disable
                     p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
                     write_unlock(&p_config_lock);
                  }
#if defined(CONFIG_X86)
                  /* smep_validate */
                  if (!P_CTRL(p_smep_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMEP)) {
                        P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smep_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smep_validate) = 0;
                        P_CTRL(p_smep_enforce) = 0;
                     }
                  }
                  /* smap_validate */
                  if (!P_CTRL(p_smap_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMAP)) {
                        P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smap_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smap_validate) = 0;
                        P_CTRL(p_smap_enforce) = 0;
                     }
                  }
#endif
                  break;

               case 3:
                  /* kint_validate */
                  if (P_CTRL(p_kint_validate) < 3)
                     p_register_notifiers();
                  P_CTRL(p_kint_validate) = 3;  // Timer + random events
                  /* pint_validate */
                  P_CTRL(p_pint_validate) = 1;  // Current
                  /* pcfi_validate */
                  P_CTRL(p_pcfi_validate) = 2;  // Full pCFI
                  /* umh_validate */
                  P_CTRL(p_umh_validate) = 1;   // Allow specific paths
                  /* msr_validate */
                  if (P_CTRL(p_msr_validate)) {
                     write_lock(&p_config_lock);
                     P_CTRL(p_msr_validate) = 0; // Disable
                     p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
                     write_unlock(&p_config_lock);
                  }
#if defined(CONFIG_X86)
                  /* smep_validate */
                  if (!P_CTRL(p_smep_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMEP)) {
                        P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smep_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smep_validate) = 0;
                        P_CTRL(p_smep_enforce) = 0;
                     }
                  }
                  /* smap_validate */
                  if (!P_CTRL(p_smap_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMAP)) {
                        P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smap_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smap_validate) = 0;
                        P_CTRL(p_smap_enforce) = 0;
                     }
                  }
#endif
                  break;

               case 4:
                  /* kint_validate */
                  if (P_CTRL(p_kint_validate) < 3)
                     p_register_notifiers();
                  P_CTRL(p_kint_validate) = 3;  // Timer + random events
                  /* pint_validate */
                  P_CTRL(p_pint_validate) = 3;  // Paranoid()
                  /* pcfi_validate */
                  P_CTRL(p_pcfi_validate) = 2;  // Full pCFI
                  /* umh_validate */
                  P_CTRL(p_umh_validate) = 2;   // Full lock-down
                  /* msr_validate */
                  if (!P_CTRL(p_msr_validate)) {
                     write_lock(&p_config_lock);
                     P_CTRL(p_msr_validate) = 1; // Enable
                     memset(p_db.p_CPU_metadata_array,0,sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids);
                     for_each_present_cpu(p_cpu) {
                        if (cpu_online(p_cpu)) {
                              smp_call_function_single(p_cpu,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
                        }
                     }
                     p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
                     write_unlock(&p_config_lock);
                  }
#if defined(CONFIG_X86)
                  /* smep_validate */
                  if (!P_CTRL(p_smep_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMEP)) {
                        P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smep_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smep_validate) = 0;
                        P_CTRL(p_smep_enforce) = 0;
                     }
                  }
                  /* smap_validate */
                  if (!P_CTRL(p_smap_validate)) {
                     if (boot_cpu_has(X86_FEATURE_SMAP)) {
                        P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                        P_CTRL(p_smap_validate) = 1;  // Enable
                     } else {
                        P_CTRL(p_smap_validate) = 0;
                        P_CTRL(p_smap_enforce) = 0;
                     }
                  }
#endif
                  break;

               default:
                  break;

            }

            p_print_log(P_LOG_STATE, "Changing 'profile_validate' from %d (%s) to %d (%s)",
                   p_tmp,
                   (p_tmp != 9) ? p_str[p_tmp] : "Custom",
                   P_CTRL(p_profile_validate),
                   (P_CTRL(p_profile_validate) != 9) ? p_str[P_CTRL(p_profile_validate)] : "Custom");
         }
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}

static int p_sysctl_profile_enforce(P_STRUCT_CTL_TABLE *p_table, int p_write,
                                     void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "Log & Accept",
      "Selective",
      "Strict",
      "Paranoid"
   };

   p_tmp = P_CTRL(p_profile_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_profile_enforce) != p_tmp) {
         if (P_CTRL(p_profile_enforce) > 3 && P_CTRL(p_profile_enforce) != 9) {
            P_CTRL(p_profile_enforce) = p_tmp;
            p_print_log(P_LOG_ISSUE, "Attempted to set 'profile_enforce' to an unsupported value");
         } else {

            switch (P_CTRL(p_profile_enforce)) {

               case 0:
                  /* kint_enforce */
                  P_CTRL(p_kint_enforce) = 0;  // Log & accept
                  /* pint_enforce */
                  P_CTRL(p_pint_enforce) = 0;  // Log & accept
                  /* pcfi_enforce */
                  P_CTRL(p_pcfi_enforce) = 0;  // Log only
                  /* umh_enforce */
                  P_CTRL(p_umh_enforce) = 0;   // Log only
#if defined(CONFIG_X86)
                  /* smep_enforce */
                  P_CTRL(p_smep_enforce) = 0;  // Log & accept
                  /* smap_enforce */
                  P_CTRL(p_smap_enforce) = 0;  // Log & accept
#endif
                  break;

               case 1:
                  /* kint_enforce */
                  P_CTRL(p_kint_enforce) = 1;  // Log only
                  /* pint_enforce */
                  P_CTRL(p_pint_enforce) = 1;  // Kill task
                  /* pcfi_enforce */
                  P_CTRL(p_pcfi_enforce) = 1;  // Kill task
                  /* umh_enforce */
                  P_CTRL(p_umh_enforce) = 1;   // Prevent execution
#if defined(CONFIG_X86)
                  /* smep_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMEP)) {
                     P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smep_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smep_enforce) = 0;
                     P_CTRL(p_smep_validate) = 0;
                  }
                  /* smap_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMAP)) {
                     P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smap_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smap_enforce) = 0;
                     P_CTRL(p_smap_validate) = 0;
                  }
#endif
                  break;

               case 2:
                  /* kint_enforce */
                  P_CTRL(p_kint_enforce) = 2;  // Panic
                  /* pint_enforce */
                  P_CTRL(p_pint_enforce) = 1;  // Kill task
                  /* pcfi_enforce */
                  P_CTRL(p_pcfi_enforce) = 1;  // Kill task
                  /* umh_enforce */
                  P_CTRL(p_umh_enforce) = 1;   // Prevent execution
#if defined(CONFIG_X86)
                  /* smep_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMEP)) {
                     P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smep_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smep_enforce) = 0;
                     P_CTRL(p_smep_validate) = 0;
                  }
                  /* smap_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMAP)) {
                     P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smap_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smap_enforce) = 0;
                     P_CTRL(p_smap_validate) = 0;
                  }
#endif
                  break;

               case 3:
                  /* kint_enforce */
                  P_CTRL(p_kint_enforce) = 2;  // Panic
                  /* pint_enforce */
                  P_CTRL(p_pint_enforce) = 2;  // Panic
                  /* pcfi_enforce */
                  P_CTRL(p_pcfi_enforce) = 2;  // Panic
                  /* umh_enforce */
                  P_CTRL(p_umh_enforce) = 2;   // Panic
#if defined(CONFIG_X86)
                  /* smep_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMEP)) {
                     P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smep_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smep_enforce) = 0;
                     P_CTRL(p_smep_validate) = 0;
                  }
                  /* smap_enforce */
                  if (boot_cpu_has(X86_FEATURE_SMAP)) {
                     P_ENABLE_SMAP_FLAG(p_pcfi_CPU_flags);
                     P_CTRL(p_smap_enforce) = 2; // Panic
                  } else {
                     P_CTRL(p_smap_enforce) = 0;
                     P_CTRL(p_smap_validate) = 0;
                  }
#endif
                  break;

               default:
                  break;

            }

            p_print_log(P_LOG_STATE, "Changing 'profile_enforce' from %d (%s) to %d (%s)",
                   p_tmp,
                   (p_tmp != 9) ? p_str[p_tmp] : "Custom",
                   P_CTRL(p_profile_enforce),
                   (P_CTRL(p_profile_enforce) != 9) ? p_str[P_CTRL(p_profile_enforce)] : "Custom");
         }
      }
   }
   p_lkrg_close_rw();

   return p_ret;
}


int p_register_comm_channel(void) {

   if ( (p_sysctl_handle = register_sysctl("lkrg", p_lkrg_sysctl_table)) == NULL) {
      return P_LKRG_GENERAL_ERROR;
   }

   return P_LKRG_SUCCESS;
}

void p_deregister_comm_channel(void) {

   unregister_sysctl_table(p_sysctl_handle);
}
