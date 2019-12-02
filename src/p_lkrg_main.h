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

#ifndef P_LKRG_MAIN_H
#define P_LKRG_MAIN_H

#define P_LKRG_UNHIDE
//#define P_LKRG_CI_X86_NO_MSR
//#define P_LKRG_PCFI_NO_STACKWALK

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#include <linux/cpufreq.h>
#include <linux/cpu_pm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#include <linux/cpuhotplug.h>
#endif
#include <linux/netdevice.h>
#include <net/netevent.h>
#include <net/addrconf.h>
#include <linux/inetdevice.h>
#include <linux/usb.h>
#include <linux/acpi.h>
#include <linux/profile.h>

#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>

#include <linux/major.h>

#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include <linux/signal.h>
#include <linux/timex.h>
#include <linux/cryptohash.h>

#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <asm/tlbflush.h>

/*
 * RHEL support
 */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

/*
 * p_lkrg modules
 */
#include "modules/print_log/p_lkrg_print_log.h"               // printing, error and debug module
#include "modules/hashing/p_lkrg_fast_hash.h"                 // Hashing module
#include "modules/ksyms/p_resolve_ksym.h"                     // Resolver module
#include "modules/database/p_database.h"                      // Database module
#include "modules/integrity_timer/p_integrity_timer.h"        // Integrity timer module
#include "modules/kmod/p_kmod.h"                              // Kernel's modules module
#include "modules/notifiers/p_notifiers.h"                    // Notifiers module
#include "modules/self-defense/hiding/p_hiding.h"             // Hiding module
#include "modules/wrap/p_struct_wrap.h"                       // Wrapping module
#include "modules/comm_channel/p_comm_channel.h"              // Communication channel (sysctl) module

/*
 * Exploit Detection
 */
#include "modules/exploit_detection/p_exploit_detection.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
 #define __GFP_REPEAT   ((__force gfp_t)___GFP_RETRY_MAYFAIL)
#endif

extern unsigned int p_init_log_level;

#endif
