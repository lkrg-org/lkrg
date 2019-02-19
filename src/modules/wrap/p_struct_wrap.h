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

#endif
