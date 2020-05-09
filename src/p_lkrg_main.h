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
#if defined(CONFIG_X86)
#include <asm/unwind.h>
#endif

//#define p_lkrg_read_only __attribute__((__section__(".data..p_lkrg_read_only"),aligned(PAGE_SIZE)))
#define __p_lkrg_read_only __attribute__((__section__(".p_lkrg_read_only")))

#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
 #define P_LKRG_MARKER1 0x3369705f6d616441
 #define P_LKRG_MARKER2 0xdeadbabedeadbabe
#else
 #define P_LKRG_MARKER1 0x3369705f
 #define P_LKRG_MARKER2 0xdeadbabe
#endif

typedef struct _p_lkrg_global_conf_structure {

   unsigned int p_kint_validate;
   unsigned int p_kint_enforce;
   unsigned int p_pint_validate;
   unsigned int p_pint_enforce;
   unsigned int p_interval;
   unsigned int p_log_level;
   unsigned int p_trigger;
   unsigned int p_block_modules;
   unsigned int p_hide_lkrg;
   unsigned int p_heartbeat;
#if defined(CONFIG_X86)
   unsigned int p_smep_validate;
   unsigned int p_smep_enforce;
#endif
   unsigned int p_umh_validate;
   unsigned int p_umh_enforce;
   unsigned int p_msr_validate;
   unsigned int p_pcfi_validate;
   unsigned int p_pcfi_enforce;

} p_lkrg_global_conf_struct;

typedef struct _p_lkrg_global_symbols_structure {

   unsigned long (*p_kallsyms_lookup_name)(const char *name);
   int (*p_freeze_processes)(void);
   void (*p_thaw_processes)(void);
#if !defined(CONFIG_ARM64)
   void (*p_flush_tlb_all)(void);
#endif
#if defined(CONFIG_X86)
   int (*p_change_page_attr_set_clr)(unsigned long *addr, int numpages,
                                     pgprot_t mask_set, pgprot_t mask_clr,
                                     int force_split, int in_flag,
                                     struct page **pages);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
   int (*p_change_memory_common)(unsigned long addr, int numpages,
                                 pgprot_t set_mask, pgprot_t clear_mask);
#endif
   int (*p_is_kernel_text_address)(unsigned long p_addr);
   void (*p_get_seccomp_filter)(struct task_struct *p_task);
   void (*p_put_seccomp_filter)(struct task_struct *p_task);
#ifdef CONFIG_SECURITY_SELINUX
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
   int *p_selinux_enabled;
#endif
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
   struct p_selinux_state *p_selinux_state;
#else
   int *p_selinux_enforcing;
#endif
#endif
#endif
   int (*p_core_kernel_text)(unsigned long p_addr);
   pmd_t *(*p_mm_find_pmd)(struct mm_struct *mm, unsigned long address);
   struct mutex *p_text_mutex;
   struct mutex *p_jump_label_mutex;
   struct text_poke_loc **p_tp_vec;
   int *p_tp_vec_nr;
#if defined(CONFIG_DYNAMIC_DEBUG)
   struct list_head *p_ddebug_tables;
   struct mutex *p_ddebug_lock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   int (*p_ddebug_remove_module_ptr)(const char *p_name);
#endif
#endif
   struct list_head *p_global_modules;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   struct mutex *p_kernfs_mutex;
#endif
   struct kset **p_module_kset;
   struct module *p_find_me;

} p_lkrg_global_syms;

typedef struct _p_lkrg_critical_variables {

   unsigned long p_dummy1;

} p_lkrg_critical_var;

typedef struct _p2_lkrg_global_ctrl_structure {

   p_lkrg_global_conf_struct ctrl;
   p_lkrg_global_syms syms;
   p_lkrg_critical_var var;

} p_lkrg_global_ctrl_struct __attribute__((aligned(PAGE_SIZE)));

typedef struct _p_lkrg_ro_page {

#if !defined(CONFIG_ARM)
   unsigned long p_marker_np1 __attribute__((aligned(PAGE_SIZE)));
#endif

   p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;

#if !defined(CONFIG_ARM)
   unsigned long p_marker_np2 __attribute__((aligned(PAGE_SIZE)));
   unsigned long p_marker_np3 __attribute__((aligned(PAGE_SIZE)));
#endif

} p_ro_page;


extern p_ro_page p_ro;

#define P_VAR(p_field) p_ro.p_lkrg_global_ctrl.var.p_field
#define P_SYM(p_field) p_ro.p_lkrg_global_ctrl.syms.p_field
#define P_CTRL(p_field) p_ro.p_lkrg_global_ctrl.ctrl.p_field
#define P_CTRL_ADDR &p_ro.p_lkrg_global_ctrl

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


#endif
