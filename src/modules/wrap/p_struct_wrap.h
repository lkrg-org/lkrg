/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module wrapping access to some critical structures
 *
 * Notes:
 *  - Wrapping some of the critical structures in the system e.g.:
 *   -> k[g/u]id_t
 *   -> accessing 'struct module' structure - since kernel 4.5 'struct module'
 *      was changed. Accessing some critical variables must be smarter now.
 *      We are wrapping the necessary fields here.
 *
 * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/diff/include/linux/module.h?id=7523e4dc5057
 *
 *
 * Timeline:
 *  - Created: 11.IX.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_WRAPPER_H
#define P_LKRG_WRAPPER_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)

static inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

static inline unsigned int p_get_uid(const kuid_t *p_from) {
   return p_from->val;
}

static inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

static inline unsigned int p_get_gid(const kgid_t *p_from) {
   return p_from->val;
}

#else

#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS

static inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

static inline unsigned int p_get_uid(const kuid_t *p_from) {
   return p_from->val;
}

static inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

static inline unsigned int p_get_gid(const kgid_t *p_from) {
   return p_from->val;
}

#else

static inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   *p_arg = p_val;
}

static inline unsigned int p_get_uid(const kuid_t *p_from) {
   return *p_from;
}

static inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   *p_arg = p_val;
}

static inline unsigned int p_get_gid(const kgid_t *p_from) {
   return *p_from;
}

#endif

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 6)

#if defined(CONFIG_GRKERNSEC)

static inline void *p_module_core(struct module *p_mod) {
   return p_mod->core_layout.base_rx;
}

static inline unsigned int p_core_text_size(struct module *p_mod) {
   return p_mod->core_layout.size_rx;
}

#else

static inline void *p_module_core(struct module *p_mod) {
   return p_mod->core_layout.base;
}

static inline unsigned int p_core_size(struct module *p_mod) {
   return p_mod->core_layout.size;
}

static inline unsigned int p_core_text_size(struct module *p_mod) {
   return p_mod->core_layout.text_size;
}

static inline unsigned int p_init_text_size(struct module *p_mod) {
   return p_mod->init_layout.text_size;
}

#endif

#else

static inline void *p_module_core(struct module *p_mod) {
   return p_mod->module_core;
}

static inline unsigned int p_init_text_size(struct module *p_mod) {
   return p_mod->init_text_size;
}

static inline unsigned int p_core_text_size(struct module *p_mod) {
   return p_mod->core_text_size;
}

static inline unsigned int p_core_size(struct module *p_mod) {
   return p_mod->core_size;
}

#endif

// #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)

#ifdef CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE

static inline unsigned long long p_jump_entry_code(const struct jump_entry *entry) {
    return (unsigned long long)&entry->code + entry->code;
}

static inline unsigned long long p_jump_entry_target(const struct jump_entry *entry) {
    return (unsigned long long)&entry->target + entry->target;
}

static inline struct static_key *p_jump_entry_key(const struct jump_entry *entry) {
    long offset = entry->key & ~3L;

    return (struct static_key *)((unsigned long)&entry->key + offset);
}

#else

static inline unsigned long long p_jump_entry_code(const struct jump_entry *entry) {
    return (unsigned long long)entry->code;
}

static inline unsigned long long p_jump_entry_target(const struct jump_entry *entry) {
    return (unsigned long long)entry->target;
}

static inline struct static_key *p_jump_entry_key(const struct jump_entry *entry)  {
    return (struct static_key *)((unsigned long)entry->key & ~3UL);
}

#endif

#if defined(CONFIG_DYNAMIC_DEBUG)
static inline int p_ddebug_remove_module(const char *p_name) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)

   return ddebug_remove_module(p_name);

#else

   return p_ddebug_remove_module_ptr(p_name);

#endif

}
#endif


/*
 * Keep this section as last here.
 * Let's define architecture dependent arguments based on the registers
 * from the intercepted process context.
 */

#ifdef CONFIG_X86

/*
 * Get
 */
static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->di;
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->si;
}

static inline unsigned long p_regs_get_fp(struct pt_regs *p_regs) {
   return p_regs->bp;
}

static inline unsigned long p_regs_get_sp(struct pt_regs *p_regs) {
   return p_regs->sp;
}

static inline unsigned long p_regs_get_ip(struct pt_regs *p_regs) {
   return p_regs->ip;
}

static inline unsigned long p_regs_get_ret(struct pt_regs *p_regs) {
   return p_regs->ax;
}

static inline unsigned long p_get_thread_sp(struct task_struct *p_arg) {
   return p_arg->thread.sp;
}

/*
 * Syscalls
 */
static inline unsigned long p_syscall_get_arg1(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_regs_get_arg1((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_syscall_get_arg2(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_regs_get_arg2((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg2(p_regs);
#endif
}

/*
 * Set
 */
static inline void p_regs_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->di = p_val;
}

static inline void p_regs_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->si = p_val;
}

/*
 * Syscalls
 */
static inline void p_syscall_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg1((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg1(p_regs, p_val);
#endif
}

static inline void p_syscall_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg2((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg2(p_regs, p_val);
#endif
}

#elif defined(CONFIG_ARM64)

/*
 * Get
 */
static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->regs[1];
}

static inline unsigned long p_regs_get_fp(struct pt_regs *p_regs) {
   return p_regs->regs[29];
}

static inline unsigned long p_regs_get_sp(struct pt_regs *p_regs) {
   return p_regs->sp;
}

static inline unsigned long p_regs_get_ip(struct pt_regs *p_regs) {
   return p_regs->pc;
}

static inline unsigned long p_regs_get_ret(struct pt_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_get_thread_sp(struct task_struct *p_arg) {
   return p_arg->thread.cpu_context.sp;
}

/*
 * Syscalls
 */
static inline unsigned long p_syscall_get_arg1(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_regs_get_arg1((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_syscall_get_arg2(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_regs_get_arg2((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg2(p_regs);
#endif
}

/*
 * Set
 */
static inline void p_regs_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->regs[0] = p_val;
}

static inline void p_regs_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->regs[1] = p_val;
}

/*
 * Syscalls
 */
static inline void p_syscall_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg1((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg1(p_regs, p_val);
#endif
}

static inline void p_syscall_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg2((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg2(p_regs, p_val);
#endif
}

#endif

static inline bool p_user_access_begin(const void __user *ptr, size_t len) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
   if (unlikely(!access_ok(VERIFY_READ,ptr,len)))
      return 0;
#if defined(CONFIG_X86) && defined(CONFIG_X86_SMAP)
   stac();
   mb();
   rmb();
#endif
   return 1;
#else
   return user_access_begin(ptr,len);
#endif
}

static inline void p_user_access_end(void) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
#if defined(CONFIG_X86) && defined(CONFIG_X86_SMAP)
   clac();
#endif
#else
   user_access_end();
#endif
}

#endif
