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

#ifndef P_LKRG_WRAPPER_H
#define P_LKRG_WRAPPER_H

inline void p_set_uid(kuid_t *p_arg, unsigned int p_val);
inline unsigned int p_get_uid(const kuid_t *p_from);
inline void p_set_gid(kgid_t *p_arg, unsigned int p_val);
inline unsigned int p_get_gid(const kgid_t *p_from);

inline void *p_module_core(struct module *p_mod);
inline unsigned int p_core_size(struct module *p_mod);
inline unsigned int p_core_text_size(struct module *p_mod);
inline unsigned int p_init_text_size(struct module *p_mod);

#endif
