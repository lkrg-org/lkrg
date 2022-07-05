/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Logging and debugging module
 *
 * Notes:
 *  - Debugging settings, error code definitions, and logging macros
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PRINT_LOG_H
#define P_LKRG_PRINT_LOG_H

/*
 * Debugging settings
 */

// Do we want to provide debug information?
#define P_LKRG_DEBUG

/* Do we want to precisely track changes of 'off' flag per each process?
 * If yes, uncomment it here */
//#define P_LKRG_TASK_OFF_DEBUG

// Do we want to precisely track all kernel .text section changes?
// By default NO. If you want it (and print relevant information)
// Uncomment it here
//#define P_LKRG_JUMP_LABEL_STEXT_DEBUG

// Debug every time we enter/exit notifiers function?
// not recommended - will be too noisy for some notifiers! :)
//#define P_LKRG_NOTIFIER_DBG

// Debug every time we enter/exit *kprobed* function?
// not recommended - will be very noisy...
//#define P_LKRG_STRONG_KPROBE_DEBUG


/*
 * Error codes
 */

// Everything is fine...
#define P_LKRG_SUCCESS                        0x0

// General error
#define P_LKRG_GENERAL_ERROR                  -1

// Can't find (resolve) "kallsyms_lookup_name" function
#define P_LKRG_RESOLVER_ERROR                 -100

// Can't initialize kmod module
#define P_LKRG_KMOD_ERROR                     -101

// Can't generate database - hashes
#define P_LKRG_DATABASE_ERROR                 -102

// Can't initialize protected features
#define P_LKRG_PROTECTED_FEATURES_ERROR       -103

// Can't register hot CPU plug[in/out] handler
#define P_LKRG_HPCPU_ERROR                    -104

// Can't register hot CPU plug[in/out] handler
#define P_LKRG_EXPLOIT_DETECTION_ERROR        -105

// User disabled loading LKRG from boot parameters
#define P_LKRG_BOOT_DISABLE_LKRG              -125

// Enable hash from IOMMU table? - not recommended!
// By default disabled
//#define P_LKRG_IOMMU_HASH_ENABLED

#define P_LKRG_KMOD_DUMP_RACE                 -200


/*
 * Logging macros
 */

// Signature in logs...
#define P_LKRG_SIGNATURE "[p_lkrg] "

#define P_LOG_LEVEL_MIN         0
#define P_LKRG_CRIT             0
#define P_LKRG_ALIVE            1
#define P_LKRG_ERR              2
#define P_LKRG_WARN             3
#define P_LKRG_INFO             4
#define P_LKRG_DBG              5
#define P_LKRG_STRONG_DBG       6
#define P_LOG_LEVEL_MAX         6

#define p_print_log(p_level, p_fmt, p_args...)                                           \
({                                                                                       \
   int p_print_ret = 0;                                                                  \
                                                                                         \
   if (p_level == P_LKRG_CRIT)                                                           \
      p_print_ret = printk(KERN_CRIT P_LKRG_SIGNATURE p_fmt, ## p_args);                 \
   else if (P_CTRL(p_log_level) >= p_level)                                              \
   switch (p_level) {                                                                    \
   case P_LKRG_ALIVE:                                                                    \
      p_print_ret = printk(KERN_NOTICE P_LKRG_SIGNATURE p_fmt, ## p_args);               \
      break;                                                                             \
   case P_LKRG_ERR:                                                                      \
      p_print_ret = printk(KERN_ERR P_LKRG_SIGNATURE p_fmt, ## p_args);                  \
      break;                                                                             \
   case P_LKRG_WARN:                                                                     \
      p_print_ret = printk(KERN_WARNING P_LKRG_SIGNATURE p_fmt, ## p_args);              \
      break;                                                                             \
   case P_LKRG_INFO:                                                                     \
      p_print_ret = printk(KERN_INFO P_LKRG_SIGNATURE p_fmt, ## p_args);                 \
      break;                                                                             \
   case P_LKRG_DBG:                                                                      \
      p_print_ret = printk(KERN_DEBUG P_LKRG_SIGNATURE p_fmt, ## p_args);                \
      break;                                                                             \
   case P_LKRG_STRONG_DBG:                                                               \
      p_print_ret = printk(KERN_DEBUG P_LKRG_SIGNATURE p_fmt, ## p_args);                \
      break;                                                                             \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define LKRG_DEBUG_TRACE notrace

#ifdef P_LKRG_DEBUG

#ifdef P_LKRG_NOTIFIER_DBG
 #define p_debug_notifier_log(p_fmt, p_args...)                                          \
                  p_debug_log(P_LKRG_STRONG_DBG, p_fmt, ## p_args)
#else
 #define p_debug_notifier_log(p_fmt, p_args...)  ({ 0x0; })
#endif

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
 #define p_debug_kprobe_log(p_fmt, p_args...)                                            \
                  p_debug_log(P_LKRG_STRONG_DBG, p_fmt, ## p_args)
 #undef LKRG_DEBUG_TRACE
 #define LKRG_DEBUG_TRACE
#else
 #define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0x0; })
#endif

#define p_debug_log p_print_log

#else

#define p_debug_log(p_level, p_fmt, p_args...)  ({ 0x0; })

#define p_debug_notifier_log(p_fmt, p_args...)  ({ 0x0; })
#define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0x0; })

#endif

#endif
