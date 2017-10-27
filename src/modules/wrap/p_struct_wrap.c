/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module wrapping access to some critical structures
 *
 * Notes:
 *  - Wrapping some of the critical structures in the system e.g.:
 *   -> k[g/u]id_t
 *   -> accesing 'struct module' structure
 *
 * Timeline:
 *  - Created: 11.IX.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)

inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

inline unsigned int p_get_uid(const kuid_t *p_from) {
   return p_from->val;
}

inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

inline unsigned int p_get_gid(const kgid_t *p_from) {
   return p_from->val;
}

#else

#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS

inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

inline unsigned int p_get_uid(const kuid_t *p_from) {
   return p_from->val;
}

inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   p_arg->val = p_val;
}

inline unsigned int p_get_gid(const kgid_t *p_from) {
   return p_from->val;
}

#else

inline void p_set_uid(kuid_t *p_arg, unsigned int p_val) {
   *p_arg = p_val;
}

inline unsigned int p_get_uid(const kuid_t *p_from) {
   return *p_from;
}

inline void p_set_gid(kgid_t *p_arg, unsigned int p_val) {
   *p_arg = p_val;
}

inline unsigned int p_get_gid(const kgid_t *p_from) {
   return *p_from;
}

#endif

#endif



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 6)


inline void *p_module_core(struct module *p_mod) {
   return p_mod->core_layout.base;
}

inline unsigned int p_core_size(struct module *p_mod) {
   return p_mod->core_layout.size;
}

inline unsigned int p_core_text_size(struct module *p_mod) {
   return p_mod->core_layout.text_size;
}

inline unsigned int p_init_text_size(struct module *p_mod) {
   return p_mod->init_layout.text_size;
}


#else

inline void *p_module_core(struct module *p_mod) {
   return p_mod->module_core;
}

inline unsigned int p_init_text_size(struct module *p_mod) {
   return p_mod->init_text_size;
}

inline unsigned int p_core_text_size(struct module *p_mod) {
   return p_mod->core_text_size;
}

inline unsigned int p_core_size(struct module *p_mod) {
   return p_mod->core_size;
}


#endif
