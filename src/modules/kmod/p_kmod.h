/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module
 *
 * Notes:
 *  - Gathering information about loaded kernel modules and tries
 *    to protect them via calculating hashes from their core_text
 *    section.
 *
 * Timeline:
 *  - Created: 09.XI.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_KERNEL_MODULES_H
#define P_LKRG_KERNEL_MODULES_H

#define P_GLOBAL_TO_MODULE(x)                                          \
({                                                                     \
   list_entry((void *)*(long *)(*(long*)x),struct module, list);       \
})

#define P_MODULE_BUFFER_RACE 5
#define P_NEW_KMOD_STEXT ((char*)0xdeadbabe)

typedef struct p_module_list_mem {

   struct module *p_mod;
   char p_name[MODULE_NAME_LEN+1];
   void *p_module_core;
   unsigned int p_core_text_size;
   uint64_t p_mod_core_text_hash;

} p_module_list_mem;


typedef struct p_module_kobj_mem {

   struct module_kobject *p_mk;
   struct kobject kobj;

   struct module *p_mod;
   char p_name[MODULE_NAME_LEN+1];
   void *p_module_core;
   unsigned int p_core_text_size;

   uint64_t p_mod_core_text_hash;

} p_module_kobj_mem;


/* Module activity events */
extern struct mutex p_module_activity;
extern struct module *p_module_activity_ptr;

void p_verify_module_live(struct module *p_mod);
void p_verify_module_going(struct module *p_mod);

int p_kmod_init(void);
int p_kmod_hash(unsigned int *p_module_list_cnt_arg, p_module_list_mem **p_mlm_tmp,
                unsigned int *p_module_kobj_cnt_arg, p_module_kobj_mem **p_mkm_tmp, char p_flag);
void p_deregister_module_notifier(void);
void p_register_module_notifier(void);

#endif
