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

#if defined(CONFIG_JUMP_LABEL) && defined(CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE)

static inline unsigned long p_jump_entry_code(const struct jump_entry *entry) {
    return (unsigned long)((unsigned long)&entry->code + entry->code);
}

static inline unsigned long p_jump_entry_target(const struct jump_entry *entry) {
    return (unsigned long)((unsigned long)&entry->target) + entry->target;
}

static inline struct static_key *p_jump_entry_key(const struct jump_entry *entry) {
    long offset = entry->key & ~3L;

    return (struct static_key *)((unsigned long)&entry->key + offset);
}

#elif defined(CONFIG_JUMP_LABEL)

static inline unsigned long p_jump_entry_code(const struct jump_entry *entry) {
    return (unsigned long)entry->code;
}

static inline unsigned long p_jump_entry_target(const struct jump_entry *entry) {
    return (unsigned long)entry->target;
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

   return P_SYM(p_ddebug_remove_module)(p_name);

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
 #if defined(CONFIG_X86_64)
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

 #else

static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->ax;
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->dx;
}

static inline unsigned long p_regs_get_arg3(struct pt_regs *p_regs) {
   return p_regs->cx;
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
   return p_regs_get_arg2((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg2(p_regs);
#endif
}

static inline unsigned long p_syscall_get_arg2(struct pt_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_regs_get_arg3((struct pt_regs *)p_regs_get_arg1(p_regs));
#else
   return p_regs_get_arg3(p_regs);
#endif
}

 #endif


/*
 * Set
 */
 #if defined(CONFIG_X86_64)

static inline void p_regs_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->di = p_val;
}

static inline void p_regs_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->si = p_val;
}

static inline void p_regs_set_ip(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->ip = p_val;
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

 #else

static inline void p_regs_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->ax = p_val;
}

static inline void p_regs_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->dx = p_val;
}

static inline void p_regs_set_arg3(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->cx = p_val;
}

static inline void p_regs_set_ip(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->ip = p_val;
}

/*
 * Syscalls
 */
static inline void p_syscall_set_arg1(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg2((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg2(p_regs, p_val);
#endif
}

static inline void p_syscall_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_regs_set_arg3((struct pt_regs *)p_regs_get_arg1(p_regs), p_val);
#else
   p_regs_set_arg3(p_regs, p_val);
#endif
}

 #endif


static inline int p_set_memory_rw(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_rw)(p_addr, p_numpages);
#else
   return P_SYM(p_change_page_attr_set_clr)(&p_addr, p_numpages,
                                            __pgprot(_PAGE_RW),
                                            __pgprot(0),
                                            0, 0, NULL);
#endif
}

static inline int p_set_memory_ro(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_ro)(p_addr, p_numpages);
#else
   return P_SYM(p_change_page_attr_set_clr)(&p_addr, p_numpages,
                                            __pgprot(0),
                                            __pgprot(_PAGE_RW),
                                            0, 0, NULL);
#endif
}

static inline int p_set_memory_np(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return 0x0;
//   return P_SYM(p_set_memory_np)(p_addr, p_numpages);
#else
   return P_SYM(p_change_page_attr_set_clr)(&p_addr, p_numpages,
                                            __pgprot(0),
                                            __pgprot(_PAGE_PRESENT),
                                            0, 0, NULL);
#endif
}

static inline int p_set_memory_p(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return 0x0;
#else
   return P_SYM(p_change_page_attr_set_clr)(&p_addr, p_numpages,
                                            __pgprot(_PAGE_PRESENT),
                                            __pgprot(0),
                                            0, 0, NULL);
#endif
}

static inline void p_lkrg_open_rw_x86(void) {

   register unsigned long p_cr0;

   preempt_disable();
   barrier();
   p_cr0 = read_cr0() ^ X86_CR0_WP;
   write_cr0(p_cr0);
   barrier();
}

static inline void p_lkrg_close_rw_x86(void) {

   register unsigned long p_cr0;

   barrier();
   p_cr0 = read_cr0() ^ X86_CR0_WP;
   write_cr0(p_cr0);
   barrier();
   preempt_enable(); //_no_resched();
}

static inline void p_lkrg_open_rw(void) {

   unsigned long p_flags;

//   preempt_disable();
   barrier();
   p_set_memory_rw((unsigned long)P_CTRL_ADDR,1);
   barrier();
   /* It's a good time to verify if everything is fine */
   p_ed_pcfi_cpu(1);
   p_tasks_read_lock(&p_flags);
   p_ed_validate_current();
   p_tasks_read_unlock(&p_flags);
}

static inline void p_lkrg_close_rw(void) {

   barrier();
   p_set_memory_ro((unsigned long)P_CTRL_ADDR,1);
   barrier();
//   preempt_enable(); //_no_resched();
}

/* ARM */
#elif defined(CONFIG_ARM)

/*
 * Get
 */
static inline unsigned long p_regs_get_arg1(struct pt_regs *p_regs) {
   return p_regs->ARM_r0;
}

static inline unsigned long p_regs_get_arg2(struct pt_regs *p_regs) {
   return p_regs->ARM_r1;
}

static inline unsigned long p_regs_get_fp(struct pt_regs *p_regs) {
   return p_regs->ARM_fp;
}

static inline unsigned long p_regs_get_sp(struct pt_regs *p_regs) {
   return frame_pointer(p_regs);
}

static inline unsigned long p_regs_get_ip(struct pt_regs *p_regs) {
   return p_regs->ARM_pc;
}

static inline unsigned long p_regs_get_ret(struct pt_regs *p_regs) {
   return p_regs->ARM_r0;
}

static inline unsigned long p_get_thread_sp(struct task_struct *p_arg) {
   return thread_saved_sp(p_arg);
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
   p_regs->ARM_r0 = p_val;
}

static inline void p_regs_set_arg2(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->ARM_r1 = p_val;
}

static inline void p_regs_set_ip(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->ARM_pc = p_val;
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

static inline int p_set_memory_rw(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_rw)(p_addr, p_numpages);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(0),
                                        __pgprot(L_PTE_RDONLY));
#endif
}

static inline int p_set_memory_ro(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_ro)(p_addr, p_numpages);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(L_PTE_RDONLY),
                                        __pgprot(0));
#endif
}

static inline void p_lkrg_open_rw(void) {

   unsigned long p_flags;

   preempt_disable();
   barrier();
   p_set_memory_rw((unsigned long)P_CTRL_ADDR,1);
   barrier();
   /* It's a good time to verify if everything is fine */
   p_ed_pcfi_cpu(1);
   p_tasks_read_lock(&p_flags);
   p_ed_validate_current();
   p_tasks_read_unlock(&p_flags);
}

static inline void p_lkrg_close_rw(void) {

   barrier();
   p_set_memory_ro((unsigned long)P_CTRL_ADDR,1);
   barrier();
   preempt_enable(); //_no_resched();
}

/* ARM64 */
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

static inline void p_regs_set_ip(struct pt_regs *p_regs, unsigned long p_val) {
   p_regs->pc = p_val;
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

static inline int p_set_memory_rw(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_rw)(p_addr, p_numpages);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(PTE_WRITE),
                                        __pgprot(PTE_RDONLY));
#endif
}

static inline int p_set_memory_ro(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_ro)(p_addr, p_numpages);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(PTE_RDONLY),
                                        __pgprot(PTE_WRITE));
#endif
}

static inline int p_set_memory_np(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_valid)(p_addr, p_numpages, 0);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(0),
                                        __pgprot(PTE_VALID));
#endif
}

static inline int p_set_memory_p(unsigned long p_addr, int p_numpages) {

#if defined(P_KERNEL_AGGRESSIVE_INLINING)
   return P_SYM(p_set_memory_valid)(p_addr, p_numpages, 1);
#else
   return P_SYM(p_change_memory_common)(p_addr, p_numpages,
                                        __pgprot(PTE_VALID),
                                        __pgprot(0));
#endif
}

static inline void p_lkrg_open_rw(void) {

   unsigned long p_flags;

   preempt_disable();
   barrier();
   p_set_memory_rw((unsigned long)P_CTRL_ADDR,1);
   barrier();
   /* It's a good time to verify if everything is fine */
   p_ed_pcfi_cpu(1);
   p_tasks_read_lock(&p_flags);
   p_ed_validate_current();
   p_tasks_read_unlock(&p_flags);
}

static inline void p_lkrg_close_rw(void) {

   barrier();
   p_set_memory_ro((unsigned long)P_CTRL_ADDR,1);
   barrier();
   preempt_enable(); //_no_resched();
}

#endif

#endif
