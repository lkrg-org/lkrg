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

static int p_smep_panic_min = 0x0;
static int p_smep_panic_max = 0x1;

static int p_umh_lock_min = 0x0;
static int p_umh_lock_max = 0x1;

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
static int p_sysctl_smep_panic(struct ctl_table *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos);
static int p_sysctl_umh_lock(struct ctl_table *p_table, int p_write,
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
      .data           = &p_lkrg_global_ctrl.p_timestamp,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = proc_dointvec_minmax,
      .extra1         = &p_timestamp_min,
      .extra2         = &p_timestamp_max,
   },
   {
      .procname       = "block_modules",
      .data           = &p_lkrg_global_ctrl.p_block_modules,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = proc_dointvec_minmax,
      .extra1         = &p_block_module_min,
      .extra2         = &p_block_module_max,
   },
   {
      .procname       = "log_level",
      .data           = &p_lkrg_global_ctrl.p_log_level,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = proc_dointvec_minmax,
      .extra1         = &p_log_level_min,
      .extra2         = &p_log_level_max,
   },
   {
      .procname       = "force_run",
      .data           = &p_lkrg_global_ctrl.p_force_run,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_force_run,
      .extra1         = &p_force_run_min,
      .extra2         = &p_force_run_max,
   },
#ifdef P_LKRG_UNHIDE
   {
      .procname       = "hide",
      .data           = &p_lkrg_global_ctrl.p_hide_module,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_hide,
      .extra1         = &p_hide_module_min,
      .extra2         = &p_hide_module_max,
   },
#endif
   {
      .procname       = "clean_message",
      .data           = &p_lkrg_global_ctrl.p_clean_message,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_clean_message,
      .extra1         = &p_clean_message_min,
      .extra2         = &p_clean_message_max,
   },
   {
      .procname       = "random_events",
      .data           = &p_lkrg_global_ctrl.p_random_events,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_random_events,
      .extra1         = &p_random_events_min,
      .extra2         = &p_random_events_max,
   },
   {
      .procname       = "ci_panic",
      .data           = &p_lkrg_global_ctrl.p_ci_panic,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_ci_panic,
      .extra1         = &p_ci_panic_min,
      .extra2         = &p_ci_panic_max,
   },
   {
      .procname       = "smep_panic",
      .data           = &p_lkrg_global_ctrl.p_smep_panic,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_smep_panic,
      .extra1         = &p_smep_panic_min,
      .extra2         = &p_smep_panic_max,
   },
   {
      .procname       = "umh_lock",
      .data           = &p_lkrg_global_ctrl.p_umh_lock,
      .maxlen         = sizeof(unsigned int),
      .mode           = 0600,
      .proc_handler   = p_sysctl_umh_lock,
      .extra1         = &p_umh_lock_min,
      .extra2         = &p_umh_lock_max,
   },
   { }
};


static int p_sysctl_force_run(struct ctl_table *p_table, int p_write,
                              void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_force_run>\n");

   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_force_run) {
         p_offload_work(0); // run integrity check!
         p_lkrg_global_ctrl.p_force_run = 0x0; // Restore 0 value - user only sees that value!
      }
   }

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

   p_tmp = p_lkrg_global_ctrl.p_hide_module;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_hide_module) {
         p_lkrg_global_ctrl.p_hide_module = p_tmp; // Restore previous state - for sync
         p_hide_itself(); // hide module!
      } else {
         p_lkrg_global_ctrl.p_hide_module = p_tmp; // Restore previous state - for sync
         p_unhide_itself(); // Unide module!
      }
   }

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

   p_tmp = p_lkrg_global_ctrl.p_clean_message;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_clean_message && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling \"clean\" message.\n");
      } else if (p_tmp && !p_lkrg_global_ctrl.p_clean_message) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling \"clean\" message.\n");
      }
   }

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

   p_tmp = p_lkrg_global_ctrl.p_random_events;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_random_events && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling LKRG verification on the random events in the system.\n");
         p_register_notifiers();
      } else if (p_tmp && !p_lkrg_global_ctrl.p_random_events) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling LKRG verification on the random events in the system.\n");
         p_deregister_notifiers();
      }
   }

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

   p_tmp = p_lkrg_global_ctrl.p_ci_panic;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_ci_panic && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling kernel panic on LKRG's CI verification failure.\n");
      } else if (p_tmp && !p_lkrg_global_ctrl.p_ci_panic) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling kernel panic on LKRG's CI verification failure.\n");
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_ci_panic>\n");

   return p_ret;
}

static int p_sysctl_smep_panic(struct ctl_table *p_table, int p_write,
                               void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_smep_panic>\n");

   p_tmp = p_lkrg_global_ctrl.p_smep_panic;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_smep_panic && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling kernel panic on LKRG's SMEP verification failure.\n");
      } else if (p_tmp && !p_lkrg_global_ctrl.p_smep_panic) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling kernel panic on LKRG's SMEP verification failure.\n");
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_smep_panic>\n");

   return p_ret;
}

static int p_sysctl_umh_lock(struct ctl_table *p_table, int p_write,
                             void __user *p_buffer, size_t *p_len, loff_t *p_pos) {

   int p_ret;
   unsigned int p_tmp;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_sysctl_umh_lock>\n");

   p_tmp = p_lkrg_global_ctrl.p_umh_lock;
   if ( (p_ret = proc_dointvec_minmax(p_table, p_write, p_buffer, p_len, p_pos)) == 0 && p_write) {
      if (p_lkrg_global_ctrl.p_umh_lock && !p_tmp) {
         p_print_log(P_LKRG_CRIT,
                     "Enabling complete lock-down of UMH interface.\n");
      } else if (p_tmp && !p_lkrg_global_ctrl.p_umh_lock) {
         p_print_log(P_LKRG_CRIT,
                     "Disabling complete lock-down of UMH interface.\n");
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sysctl_umh_lock>\n");

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
