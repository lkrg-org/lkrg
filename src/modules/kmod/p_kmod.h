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


typedef struct _p_lkrg_global_ctrl_structure {

   unsigned int p_timestamp;
   unsigned int p_log_level;
   unsigned int p_force_run;
   unsigned int p_block_modules;
   unsigned int p_hide_module;
   unsigned int p_clean_message;
   unsigned int p_random_events;
   unsigned int p_ci_panic;
   unsigned int p_smep_panic;
   unsigned int p_umh_lock;

} p_lkrg_global_ctrl_struct;


extern p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;

extern struct list_head *p_ddebug_tables;
extern struct mutex *p_ddebug_lock;
extern struct list_head *p_global_modules;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
extern struct mutex *p_kernfs_mutex;
#endif
extern struct kset **p_module_kset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
extern int (*p_ddebug_remove_module_ptr)(const char *p_name);
#endif

/* Module activity events */
extern struct mutex p_module_activity;
extern struct module *p_module_activity_ptr;

int p_block_always(void);

int p_kmod_init(void);
int p_kmod_hash(unsigned int *p_module_list_cnt_arg, p_module_list_mem **p_mlm_tmp,
                unsigned int *p_module_kobj_cnt_arg, p_module_kobj_mem **p_mkm_tmp, char p_flag);
void p_deregister_module_notifier(void);
void p_register_module_notifier(void);

#endif
