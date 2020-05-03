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

static int p_kint_validate_min = 0x0;
static int p_kint_validate_max = 0x3;

static int p_kint_enforce_min = 0x0;
static int p_kint_enforce_max = 0x2;

static int p_pint_validate_min = 0x0;
static int p_pint_validate_max = 0x3;

static int p_pint_enforce_min = 0x0;
static int p_pint_enforce_max = 0x2;

static int p_interval_min = 0x5;
static int p_interval_max = 0x708; // 1800

static int p_log_level_min = P_LOG_LEVEL_NONE;
static int p_log_level_max = P_LOG_LEVEL_MAX - 1;

static int p_block_module_min = 0x0;
static int p_block_module_max = 0x1;

static int p_trigger_min = 0x0;
static int p_trigger_max = 0x1;

#ifdef P_LKRG_UNHIDE
static int p_hide_lkrg_min = 0x0;
static int p_hide_lkrg_max = 0x1;
#endif

static int p_heartbeat_min = 0x0;
static int p_heartbeat_max = 0x1;

#ifdef CONFIG_X86
static int p_smep_validate_min = 0x0;
static int p_smep_validate_max = 0x1;

static int p_smep_enforce_min = 0x0;
static int p_smep_enforce_max = 0x2;
#endif

static int p_umh_validate_min = 0x0;
static int p_umh_validate_max = 0x2;

static int p_umh_enforce_min = 0x0;
static int p_umh_enforce_max = 0x2;

static int p_msr_validate_min = 0x0;
static int p_msr_validate_max = 0x1;

static int p_pcfi_validate_min = 0x0;
static int p_pcfi_validate_max = 0x2;

static int p_pcfi_enforce_min = 0x0;
static int p_pcfi_enforce_max = 0x2;


static int p_sysctl_kint_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_kint_enforce(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pint_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pint_enforce(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_interval(struct ctl_table *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_block_modules(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_log_level(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_trigger(struct ctl_table *p_table, int p_write,
                            void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#ifdef P_LKRG_UNHIDE
static int p_sysctl_hide(struct ctl_table *p_table, int p_write,
                         void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_heartbeat(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#ifdef CONFIG_X86
static int p_sysctl_smep_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_smep_enforce(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
#endif
static int p_sysctl_umh_validate(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_umh_enforce(struct ctl_table *p_table, int p_write,
                                void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_msr_validate(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pcfi_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_pcfi_enforce(struct ctl_table *p_table, int p_write,
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
      .data           = &P_CTRL(p_log_level),
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
#ifdef P_LKRG_UNHIDE
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
#ifdef CONFIG_X86
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
   { }
};


static int p_sysctl_kint_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "DISABLED",
      "MANUAL",
      "PERIODICALLY",
      "PERIODICALLY + RANDOM EVENTS"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_kint_validate>\n");

   p_tmp = P_CTRL(p_kint_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_kint_validate) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"kint_validate\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_kint_validate),
                     p_str[P_CTRL(p_kint_validate)]
                     );

         /* Random events */
         if (p_tmp < 0x3 && P_CTRL(p_kint_validate) == 0x3) {
            p_register_notifiers();
         } else if (p_tmp == 0x3 && P_CTRL(p_kint_validate) < 0x3) {
            p_deregister_notifiers();
         }
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_kint_validate>\n");

   return p_ret;
}

static int p_sysctl_kint_enforce(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "LOG & ACCEPT",
#ifdef CONFIG_X86
      "LOG ONLY (For SELinux and CR0.WP LOG & RESTORE)",
#else
      "LOG ONLY (For SELinux LOG & RESTORE)",
#endif
      "PANIC"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_kint_enforce>\n");

   p_tmp = P_CTRL(p_kint_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_kint_enforce) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"kint_enforce\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_kint_enforce),
                     p_str[P_CTRL(p_kint_enforce)]
                     );
#ifdef CONFIG_X86
         if (P_CTRL(p_kint_enforce)) {
            P_ENABLE_WP_FLAG(p_pcfi_CPU_flags);
         }
#endif
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_kint_enforce>\n");

   return p_ret;
}

static int p_sysctl_pint_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "DISABLED",
      "CURRENT",
      "CURRENT + WAKING_UP",
      "ALL TASKS"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_pint_validate>\n");

   p_tmp = P_CTRL(p_pint_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pint_validate) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"pint_validate\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_pint_validate),
                     p_str[P_CTRL(p_pint_validate)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_pint_validate>\n");

   return p_ret;
}

static int p_sysctl_pint_enforce(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "LOG & ACCEPT",
      "KILL TASK",
      "PANIC"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_pint_enforce>\n");

   p_tmp = P_CTRL(p_pint_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pint_enforce) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"pint_enforce\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_pint_enforce),
                     p_str[P_CTRL(p_pint_enforce)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_pint_enforce>\n");

   return p_ret;
}


static int p_sysctl_interval(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {
   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_interval>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      p_print_log(P_LKRG_CRIT, "[KINT] New interval => %d\n",P_CTRL(p_interval));
      p_offload_work(0); // run integrity check!
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_interval>\n");

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
      } else if (p_tmp && !P_CTRL(p_block_modules)) {
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
   static const char * const p_log_level_string[] = {
      "NONE",
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


static int p_sysctl_trigger(struct ctl_table *p_table, int p_write,
                            void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_trigger>\n");

   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_trigger)) {
         p_offload_work(0); // run integrity check!
         P_CTRL(p_trigger) = 0x0; // Restore 0 value - user only sees that value!
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_trigger>\n");

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

   p_tmp = P_CTRL(p_hide_lkrg);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_hide_lkrg)) {
         P_CTRL(p_hide_lkrg) = p_tmp; // Restore previous state - for sync
         p_hide_itself(); // hide module!
      } else {
         P_CTRL(p_hide_lkrg) = p_tmp; // Restore previous state - for sync
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

static int p_sysctl_heartbeat(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_heartbeat>\n");

   p_tmp = P_CTRL(p_heartbeat);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_heartbeat) && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling heartbeat message.\n");
      } else if (p_tmp && !P_CTRL(p_heartbeat)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling heartbeat message.\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_heartbeat>\n");

   return p_ret;
}

#ifdef CONFIG_X86
static int p_sysctl_smep_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_smep_validate>\n");

   p_tmp = P_CTRL(p_smep_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smep_validate) && !p_tmp) {
         if (cpu_has(&cpu_data(smp_processor_id()), X86_FEATURE_SMEP)) {
            p_print_log(P_LKRG_CRIT,
                   "Enabling SMEP validation feature.\n");
            P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
         } else {
            p_print_log(P_LKRG_ERR,
                   "System does NOT support SMEP. LKRG can't enable SMEP validation :(\n");
            P_CTRL(p_smep_validate) = 0x0;
            P_CTRL(p_smep_enforce) = 0x0;
         }
      } else if (p_tmp && !P_CTRL(p_smep_validate)) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling SMEP validation feature.\n");
      }

   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_smep_validate>\n");

   return p_ret;
}

static int p_sysctl_smep_enforce(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "LOG & ACCEPT",
      "LOG & RESTORE",
      "PANIC"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_smep_enforce>\n");

   p_tmp = P_CTRL(p_smep_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_smep_enforce) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"smep_enforce\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_smep_enforce),
                     p_str[P_CTRL(p_smep_enforce)]
                     );
         if (cpu_has(&cpu_data(smp_processor_id()), X86_FEATURE_SMEP)) {
            P_ENABLE_SMEP_FLAG(p_pcfi_CPU_flags);
         } else {
            p_print_log(P_LKRG_ERR,
                   "System does NOT support SMEP. LKRG's SMEP validation will be disabled :(\n");
            P_CTRL(p_smep_enforce) = 0x0;
            P_CTRL(p_smep_validate) = 0x0;
         }
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_smep_enforce>\n");

   return p_ret;
}
#endif

static int p_sysctl_umh_validate(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "Disable protection",
      "Whitelist UMH paths",
      "Completely block UMH"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_umh_validate>\n");

   p_tmp = P_CTRL(p_umh_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_umh_validate) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"umh_validate\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_umh_validate),
                     p_str[P_CTRL(p_umh_validate)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_umh_validate>\n");

   return p_ret;
}

static int p_sysctl_umh_enforce(struct ctl_table *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "LOG ONLY",
      "PREVENT EXECUTION",
      "PANIC"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_umh_enforce>\n");

   p_tmp = P_CTRL(p_umh_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_umh_enforce) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"umh_enforce\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_umh_enforce),
                     p_str[P_CTRL(p_umh_enforce)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_umh_enforce>\n");

   return p_ret;
}

static int p_sysctl_msr_validate(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   int p_cpu;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_msr_validate>\n");

   p_tmp = P_CTRL(p_msr_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_msr_validate) && !p_tmp) {
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
                     "Enabling MSRs verification during Kernel Integrity validation (KINT).\n");
      } else if (p_tmp && !P_CTRL(p_msr_validate)) {
         p_offload_work(0); // run integrity check!
         schedule();
         spin_lock(&p_db_lock);
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
         spin_unlock(&p_db_lock);
         p_print_log(P_LKRG_CRIT,
                     "Disabling MSRs verification during Kernel Integrity validation (KINT).\n");
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_msr_validate>\n");

   return p_ret;
}

static int p_sysctl_pcfi_validate(struct ctl_table *p_table, int p_write,
                                  void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   static const char * const p_str[] = {
      "Disabled",
      "No stackwalk (weak)",
      "Fully enabled"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_pcfi_validate>\n");

   p_tmp = P_CTRL(p_pcfi_validate);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pcfi_validate) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"pcfi_validate\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_pcfi_validate),
                     p_str[P_CTRL(p_pcfi_validate)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_pcfi_validate>\n");

   return p_ret;
}

static int p_sysctl_pcfi_enforce(struct ctl_table *p_table, int p_write,
                                 void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;
   char *p_str[] = {
      "LOG ONLY",
      "KILL TASK",
      "PANIC"
   };

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_pcfi_enforce>\n");

   p_tmp = P_CTRL(p_pcfi_enforce);
   p_lkrg_open_rw();
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (P_CTRL(p_pcfi_enforce) != p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Changing \"pcfi_enforce\" logic. From Old[%d | %s] to new[%d | %s] one.\n",
                     p_tmp,
                     p_str[p_tmp],
                     P_CTRL(p_pcfi_enforce),
                     p_str[P_CTRL(p_pcfi_enforce)]
                     );
      }
   }
   p_lkrg_close_rw();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_pcfi_enforce>\n");

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
