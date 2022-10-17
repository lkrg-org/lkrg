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
#define P_BOOT_DISABLE_LKRG "nolkrg"

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

#include <linux/vmalloc.h>
#include <linux/ftrace.h>

#include <linux/preempt.h>
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#if ( (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,72)) && \
      (!(defined(RHEL_RELEASE_CODE)) || \
         RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 4)))
static inline unsigned long get_random_long(void) {
   unsigned long p_ret;
   get_random_bytes(&p_ret, sizeof(p_ret));
   return p_ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
#define p_kzfree kzfree
#else
#define p_kzfree kfree_sensitive
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0) && \
    (!defined(RHEL_RELEASE_CODE) || RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9, 0))
#define p_read_cpu_lock get_online_cpus
#define p_read_cpu_unlock put_online_cpus
#else
#define p_read_cpu_lock cpus_read_lock
#define p_read_cpu_unlock cpus_read_unlock
#endif

#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <asm/tlbflush.h>
#if defined(CONFIG_X86) && defined(CONFIG_UNWINDER_ORC)
#include <asm/unwind.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task_stack.h>
#endif

/*
 * Define kmem_cache_create() flags:
 *  - LKRG has used to leverage SLAB_HWCACHE_ALIGN but memory overhead
 *    may be too significant for LKRG's use cases
 *  - Since the kernel 4.5+ we can use SLAB_ACCOUNT to make sure
 *    that LKRG's caches are standalone
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
 #define P_LKRG_CACHE_FLAGS 0
#else
 #define P_LKRG_CACHE_FLAGS SLAB_ACCOUNT
#endif


/*
 * Some custom compilation of the kernel might aggresively inline
 * critical functions (from LKRG perspective). That's problematic
 * for the project. However, some of the problems *might* be solved
 * by uncommenting following definition. However, not all of them
 * so you need to experiment.
 */
//#define P_KERNEL_AGGRESSIVE_INLINING 1

//#define p_lkrg_read_only __attribute__((__section__(".data..p_lkrg_read_only"),aligned(PAGE_SIZE)))
#define __p_lkrg_read_only __attribute__((__section__(".p_lkrg_read_only")))

#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
 #define P_LKRG_MARKER1 0x3369705f6d616441
 #define P_LKRG_MARKER2 0xdeadbabedeadbabe
#else
 #define P_LKRG_MARKER1 0x3369705f
 #define P_LKRG_MARKER2 0xdeadbabe
#endif

#if defined(CONFIG_SECURITY_SELINUX_DEVELOP) && !defined(CONFIG_GCC_PLUGIN_RANDSTRUCT)
#define P_SELINUX_VERIFY
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0) || \
 (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,118) && LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)) || \
 (LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,191) && LINUX_VERSION_CODE < KERNEL_VERSION(4,20,0)) || \
 (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,233) && LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
#define P_LKRG_UNEXPORTED_MODULE_ADDRESS
#endif

#define nitems(val)      (sizeof(val) / sizeof(val[0]))

typedef struct _p_lkrg_global_conf_structure {

#if defined(CONFIG_X86)
   unsigned int p_smep_validate;
   unsigned int p_smap_validate;
#endif
   unsigned int p_pcfi_validate;
   unsigned int p_pint_validate;
   unsigned int p_kint_validate;
   unsigned int p_log_level;
   unsigned int p_block_modules;
   unsigned int p_msr_validate;
   unsigned int p_heartbeat;
   unsigned int p_interval;
   unsigned int p_umh_validate;
#if defined(CONFIG_X86)
   unsigned int p_smep_enforce;
   unsigned int p_smap_enforce;
#endif
   unsigned int p_pcfi_enforce;
   unsigned int p_pint_enforce;
   unsigned int p_kint_enforce;
   unsigned int p_trigger;
   unsigned int p_hide_lkrg;
   unsigned int p_umh_enforce;
   /* Profiles */
   unsigned int p_profile_validate;
   unsigned int p_profile_enforce;

} p_lkrg_global_conf_struct;

typedef struct _p_lkrg_global_symbols_structure {

   unsigned long (*p_kallsyms_lookup_name)(const char *name);
   int (*p_freeze_processes)(void);
   void (*p_thaw_processes)(void);
#if !defined(CONFIG_ARM64)
   void (*p_flush_tlb_all)(void);
#endif

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   int (*p_set_memory_ro)(unsigned long addr, int numpages);
   int (*p_set_memory_rw)(unsigned long addr, int numpages);
 #if defined(CONFIG_X86)
   ;
//   int (*p_set_memory_np)(unsigned long addr, int numpages);
 #elif defined(CONFIG_ARM64)
   int (*p_set_memory_valid)(unsigned long addr, int numpages, int enable);
 #endif
#else
 #if defined(CONFIG_X86)
   int (*p_change_page_attr_set_clr)(unsigned long *addr, int numpages,
                                     pgprot_t mask_set, pgprot_t mask_clr,
                                     int force_split, int in_flag,
                                     struct page **pages);
 #elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
   int (*p_change_memory_common)(unsigned long addr, int numpages,
                                 pgprot_t set_mask, pgprot_t clear_mask);
 #endif
#endif
   int (*p___kernel_text_address)(unsigned long p_addr);
#if defined(CONFIG_SECCOMP)
   void (*p_get_seccomp_filter)(struct task_struct *p_task);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
   void (*p_put_seccomp_filter)(struct seccomp_filter *p_filter);
#else
   void (*p_put_seccomp_filter)(struct task_struct *p_task);
#endif
#endif
#ifdef CONFIG_SECURITY_SELINUX
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
   int *p_selinux_enabled;
#endif
#ifdef P_SELINUX_VERIFY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
   struct p_selinux_state *p_selinux_state;
#else
   int *p_selinux_enforcing;
#endif
#endif
#endif
   int (*p_core_kernel_text)(unsigned long p_addr);
   pmd_t *(*p_mm_find_pmd)(struct mm_struct *mm, unsigned long address);
   struct mutex *p_jump_label_mutex;
   struct mutex *p_text_mutex;
   struct text_poke_loc **p_tp_vec;
   int *p_tp_vec_nr;
#if defined(CONFIG_DYNAMIC_DEBUG)
   struct list_head *p_ddebug_tables;
   struct mutex *p_ddebug_lock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   int (*p_ddebug_remove_module)(const char *p_name);
#endif
#endif
   struct list_head *p_modules;
   struct kset **p_module_kset;
#if defined(CONFIG_X86)
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
   void (*p_native_write_cr4)(unsigned long p_val);
 #endif
#endif
#ifdef P_LKRG_UNEXPORTED_MODULE_ADDRESS
   struct module* (*p___module_address)(unsigned long p_val);
   struct module* (*p___module_text_address)(unsigned long p_val);
#endif
   struct module* (*p_find_module)(const char *name);
   struct mutex *p_module_mutex;
   int (*p_kallsyms_on_each_symbol)(int (*)(void *, const char *, struct module *, unsigned long), void *);
#if defined(CONFIG_FUNCTION_TRACER)
   struct ftrace_rec_iter *(*p_ftrace_rec_iter_start)(void);
   struct ftrace_rec_iter *(*p_ftrace_rec_iter_next)(struct ftrace_rec_iter *iter);
   struct dyn_ftrace *(*p_ftrace_rec_iter_record)(struct ftrace_rec_iter *iter);
   struct mutex *p_ftrace_lock;
#endif
#if defined(CONFIG_OPTPROBES)
   void (*p_wait_for_kprobe_optimizer)(void);
#endif
   struct module *p_find_me;
   unsigned int p_state_init;

} p_lkrg_global_syms;

#ifdef P_LKRG_UNEXPORTED_MODULE_ADDRESS
#define LKRG_P_MODULE_ADDRESS(p_addr)      P_SYM(p___module_address)(p_addr)
#define LKRG_P_MODULE_TEXT_ADDRESS(p_addr) P_SYM(p___module_text_address)(p_addr)
#else
#define LKRG_P_MODULE_ADDRESS(p_addr)      __module_address(p_addr)
#define LKRG_P_MODULE_TEXT_ADDRESS(p_addr) __module_text_address(p_addr)
#endif

typedef struct _p_lkrg_critical_variables {

   unsigned long p_dummy1;

} p_lkrg_critical_var;

typedef struct _p2_lkrg_global_ctrl_structure {

   p_lkrg_global_conf_struct ctrl;
   p_lkrg_global_syms syms;
   p_lkrg_critical_var var;

} p_lkrg_global_ctrl_struct __attribute__((aligned(PAGE_SIZE)));

typedef struct _p_lkrg_ro_page {

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   unsigned long p_marker_np1 __attribute__((aligned(PAGE_SIZE)));
#endif

   p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;

#if !defined(CONFIG_ARM) && (!defined(P_KERNEL_AGGRESSIVE_INLINING) && defined(CONFIG_X86))
   unsigned long p_marker_np2 __attribute__((aligned(PAGE_SIZE)));
   unsigned long p_marker_np3 __attribute__((aligned(PAGE_SIZE)));
#endif

} p_ro_page;


extern p_ro_page p_ro;

#define P_VAR(p_field) p_ro.p_lkrg_global_ctrl.var.p_field
#define P_SYM(p_field) p_ro.p_lkrg_global_ctrl.syms.p_field
#define P_CTRL(p_field) p_ro.p_lkrg_global_ctrl.ctrl.p_field
#define P_CTRL_ADDR &p_ro.p_lkrg_global_ctrl

#define P_SYM_INIT(sym, type) \
   if (!(P_SYM(p_ ## sym) = (type)P_SYM(p_kallsyms_lookup_name)(#sym))) { \
      p_print_log(P_LOG_FATAL, "Can't find '" #sym "'"); \
      goto p_sym_error; \
   }

/*
 * LKRG counter lock
 */
typedef struct p_lkrg_counter_lock {

   atomic_t p_counter;
   spinlock_t p_lock;

} p_lkrg_counter_lock;

/* Counter lock API */
static inline void p_lkrg_counter_lock_init(p_lkrg_counter_lock *p_arg) {

   spin_lock_init(&p_arg->p_lock);
   smp_mb();
   atomic_set(&p_arg->p_counter, 0);
   smp_mb();
}

static inline unsigned long p_lkrg_counter_lock_trylock(p_lkrg_counter_lock *p_arg, unsigned long *p_flags) {

   local_irq_save(*p_flags);
   if (!spin_trylock(&p_arg->p_lock)) {
      local_irq_restore(*p_flags);
      return 0;
   }
   return 1;
}

static inline void p_lkrg_counter_lock_lock(p_lkrg_counter_lock *p_arg, unsigned long *p_flags) {

   spin_lock_irqsave(&p_arg->p_lock, *p_flags);
}

static inline void p_lkrg_counter_lock_unlock(p_lkrg_counter_lock *p_arg, unsigned long *p_flags) {

   spin_unlock_irqrestore(&p_arg->p_lock, *p_flags);
}

static inline void p_lkrg_counter_lock_val_inc(p_lkrg_counter_lock *p_arg) {

   smp_mb();
   atomic_inc(&p_arg->p_counter);
   smp_mb();
}

static inline void p_lkrg_counter_lock_val_dec(p_lkrg_counter_lock *p_arg) {

   smp_mb();
   atomic_dec(&p_arg->p_counter);
   smp_mb();
}

static inline int p_lkrg_counter_lock_val_read(p_lkrg_counter_lock *p_arg) {

   register int p_ret;

   smp_mb();
   p_ret = atomic_read(&p_arg->p_counter);
   smp_mb();

   return p_ret;
}
/* End */

/*
 * LKRG modules
 */
#include "modules/print_log/p_lkrg_print_log.h"               // printing, error and debug module
#include "modules/hashing/p_lkrg_fast_hash.h"                 // Hashing module
#include "modules/ksyms/p_resolve_ksym.h"                     // Resolver module
#include "modules/database/p_database.h"                      // Database module
#include "modules/integrity_timer/p_integrity_timer.h"        // Integrity timer module
#include "modules/kmod/p_kmod.h"                              // Kernel's modules module
#include "modules/notifiers/p_notifiers.h"                    // Notifiers module
#include "modules/self-defense/hiding/p_hiding.h"             // Hiding module
#include "modules/exploit_detection/p_exploit_detection.h"    // Exploit Detection
#include "modules/wrap/p_struct_wrap.h"                       // Wrapping module
#include "modules/comm_channel/p_comm_channel.h"              // Communication channel (sysctl) module


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
 #define __GFP_REPEAT   ((__force gfp_t)___GFP_RETRY_MAYFAIL)
#endif

#if !defined(CONFIG_KPROBES)
 #error "LKRG requires CONFIG_KPROBES"
#elif !defined(CONFIG_HAVE_KRETPROBES)
 #error "CONFIG_KPROBES is enabled, however CONFIG_HAVE_KRETPROBES is not found. LKRG requires both."
#endif

#if !defined(CONFIG_MODULE_UNLOAD)
 #error "LKRG requires CONFIG_MODULE_UNLOAD"
#endif

#if !defined(CONFIG_KALLSYMS_ALL)
 #error "LKRG requires CONFIG_KALLSYMS_ALL"
#endif

#if !defined(CONFIG_JUMP_LABEL)
 #error "LKRG requires CONFIG_JUMP_LABEL"
#endif

#if !defined(CONFIG_STACKTRACE)
/*
 * A #warning in this header file would be printed too many times during build,
 * so let's only do that for something truly important, which the below is not.
 */
// #warning "LKRG does NOT require CONFIG_STACKTRACE. However, in case of pCFI violation, LKRG won't be able to dump full stack-trace."
#endif

#if defined(CONFIG_PREEMPT_RT)
 #error "LKRG does not support RT kernels (PREEMPT_RT is enabled)"
#endif

#if defined(CONFIG_TRIM_UNUSED_KSYMS) && !defined(CONFIG_SECURITY_LKRG)
 #error "LKRG requires CONFIG_TRIM_UNUSED_KSYMS to be disabled if it should be built as an out-of-tree kernel module"
#endif

#endif
