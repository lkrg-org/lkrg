/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module wrapping access to 'struct module'
 *
 * Notes:
 *  - Since kernel 4.5 'struct module' was changed. Accessing some critical
 *    variables must be more 'smart' now. We are wrapping necessary fields here.
 *
 * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/diff/include/linux/module.h?id=7523e4dc5057
 *
 *
 * Timeline:
 *  - Created: 16.V.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */


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
