/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Error module
 *
 * Notes:
 *  - Error code definitions
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

#include "p_lkrg_log_level_shared.h"

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

// Enable hash from IOMMU table? - not recommended!
// By default disabled
//#define P_LKRG_IOMMU_HASH_ENABLED

// Signature in logs...
#define P_LKRG_SIGNATURE "[p_lkrg] "

//#define P_LKRG_PRINT __P_LKRG_CRIT

#define P_LKRG_ALIVE            1
#define P_LKRG_CRIT             2
#define P_LKRG_ERR              3
#define P_LKRG_WARN             4
#define P_LKRG_INFO             5

#define P_LKRG_DBG              6
#define P_LKRG_STRONG_DBG       7


#define __P_LKRG_CRIT           KERN_CRIT
#define __P_LKRG_ERR            KERN_ERR
#define __P_LKRG_WARN           KERN_WARNING
#define __P_LKRG_INFO           KERN_INFO

#define __P_LKRG_ALIVE          __P_LKRG_CRIT

#define __P_LKRG_DBG            KERN_ALERT
#define __P_LKRG_STRONG_DBG     __P_LKRG_DBG


/*
#ifdef P_LKRG_DEBUG

#define p_print_log(p_level, p_fmt, p_args...)                                           \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_level == P_LKRG_CRIT) {                                                         \
      p_print_ret = p_print_crit(__P_LKRG_CRIT P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   } else if (p_level == P_LKRG_ALIVE) {                                                 \
      p_print_ret = p_print_alive(__P_LKRG_ALIVE P_LKRG_SIGNATURE p_fmt, ## p_args);     \
   } else if (p_level == P_LKRG_ERR) {                                                   \
      p_print_ret = p_print_err(__P_LKRG_ERR P_LKRG_SIGNATURE p_fmt, ## p_args);         \
   } else if (p_level == P_LKRG_WARN) {                                                  \
      p_print_ret = p_print_warn(__P_LKRG_WARN P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   } else if (p_level == P_LKRG_INFO) {                                                  \
      p_print_ret = p_print_info(__P_LKRG_INFO P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   } else if (p_level == P_LKRG_DBG) {                                                   \
      p_print_ret = p_print_dbg(__P_LKRG_DBG P_LKRG_SIGNATURE p_fmt, ## p_args);         \
   } else if (p_level == P_LKRG_STRONG_DBG) {                                            \
      p_print_ret = p_print_dbg2(__P_LKRG_STRONG_DBG P_LKRG_SIGNATURE p_fmt, ## p_args); \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})


#else
*/
#define p_print_log(p_level, p_fmt, p_args...)                                           \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_level == P_LKRG_CRIT) {                                                         \
      p_print_ret = p_print_crit(__P_LKRG_CRIT P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   } else if (p_level == P_LKRG_ALIVE) {                                                 \
      p_print_ret = p_print_alive(__P_LKRG_ALIVE P_LKRG_SIGNATURE p_fmt, ## p_args);     \
   } else if (p_level == P_LKRG_ERR) {                                                   \
      p_print_ret = p_print_err(__P_LKRG_ERR P_LKRG_SIGNATURE p_fmt, ## p_args);         \
   } else if (p_level == P_LKRG_WARN) {                                                  \
      p_print_ret = p_print_warn(__P_LKRG_WARN P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   } else if (p_level == P_LKRG_INFO) {                                                  \
      p_print_ret = p_print_info(__P_LKRG_INFO P_LKRG_SIGNATURE p_fmt, ## p_args);       \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

//#endif



#define p_print_crit(p_fmt, p_args...)                                                   \
({                                                                                       \
   printk(p_fmt, ## p_args);                                                             \
})

#define p_print_alive(p_fmt, p_args...)                                                  \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_ALIVE) {                            \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define p_print_err(p_fmt, p_args...)                                                    \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_ERRORS) {                           \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define p_print_warn(p_fmt, p_args...)                                                   \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_WARNS) {                            \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define p_print_info(p_fmt, p_args...)                                                   \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_INFOS) {                            \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})


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
#else
 #define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0x0; })
#endif

#define p_debug_log(p_level, p_fmt, p_args...)                                           \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_level == P_LKRG_DBG) {                                                          \
      p_print_ret = p_print_dbg(__P_LKRG_DBG P_LKRG_SIGNATURE p_fmt, ## p_args);         \
   } else if (p_level == P_LKRG_STRONG_DBG) {                                            \
      p_print_ret = p_print_dbg2(__P_LKRG_STRONG_DBG P_LKRG_SIGNATURE p_fmt, ## p_args); \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define p_print_dbg(p_fmt, p_args...)                                                    \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_DBG) {                              \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#define p_print_dbg2(p_fmt, p_args...)                                                   \
({                                                                                       \
   int p_print_ret = 0x0;                                                                \
                                                                                         \
   if (p_lkrg_global_ctrl.p_log_level >= P_LOG_LEVEL_STRONG_DBG) {                       \
      p_print_ret = printk(p_fmt, ## p_args);                                            \
   }                                                                                     \
                                                                                         \
   p_print_ret;                                                                          \
})

#else

#define p_debug_log(p_level, p_fmt, p_args...)  ({ 0x0; })

#define p_print_dbg(p_fmt, p_args...)           ({ 0x0; })
#define p_print_dbg2(p_fmt, p_args...)          ({ 0x0; })

#define p_debug_notifier_log(p_fmt, p_args...)  ({ 0x0; })
#define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0x0; })

#endif

#endif
