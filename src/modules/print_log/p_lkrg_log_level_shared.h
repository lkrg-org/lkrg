/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Log level definitions
 *
 * Notes:
 *  - Log level definitions shared with user-mode client
 *
 * Timeline:
 *  - Created: 31.III.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_LOG_LEVEL_SHARED_H
#define P_LKRG_LOG_LEVEL_SHARED_H


/*
 * Debugging definitions...
 */

// Do we want to provide debug information?
#define P_LKRG_DEBUG

// Debug every time we enter/exit notifiers function?
// not recommended - will be too noisy for some notifiers! :)
//#define P_LKRG_NOTIFIER_DBG

// Debug every time we enter/exit *kprobed* function?
// not recommended - will be very noisy...
//#define P_LKRG_STRONG_KPROBE_DEBUG

enum P_LOG_LEVELS {

   P_LOG_LEVEL_NONE,
   P_LOG_LEVEL_ALIVE,
   P_LOG_LEVEL_ERRORS,
   P_LOG_LEVEL_WARNS,
   P_LOG_LEVEL_INFOS,

#ifdef P_LKRG_DEBUG

   P_LOG_LEVEL_DBG,
   P_LOG_LEVEL_STRONG_DBG,

#endif

   P_LOG_LEVEL_MAX

};

#endif
