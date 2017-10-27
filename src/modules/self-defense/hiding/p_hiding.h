/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - (Un)Hiding module
 *
 * Notes:
 *  - (Un)Hide itself from the module system activity components
 *
 * Timeline:
 *  - Created: 10.XI.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_HIDING_MODULE_H
#define P_LKRG_HIDING_MODULE_H

#define P_HIDE_FROM_MODULE_LIST(p_arg)                                     \
do {                                                                       \
   p_debug_log(P_LKRG_DBG, "Hiding module [%s | %p]\n",                    \
                                     p_arg->name,p_arg);                   \
   list_del(&p_arg->list);                                                 \
   /* p_arg->list.next->prev = p_arg->list.prev; */                        \
   /* p_arg->list.prev->next = p_arg->list.next; */                        \
} while(0)

#define P_HIDE_FROM_KOBJ(p_arg)                                            \
do {                                                                       \
   if (p_arg->holders_dir && p_arg->holders_dir->parent) {                 \
      p_debug_log(P_LKRG_DBG, "Deleting KOBJ [%p]\n",                      \
                               p_arg->holders_dir->parent);                \
      kobject_del(p_arg->holders_dir->parent);                             \
   }                                                                       \
} while(0)

/*
#define P_HIDE_FROM_KOBJ(p_arg)                                            \
do {                                                                       \
   p_debug_log(P_LKRG_DBG, "Deleting KOBJ [%p]\n",                         \
                                  &p_arg->mkobj.kobj);                     \
   kobject_del(&p_arg->mkobj.kobj);                                        \
   p_arg->sect_attrs  = NULL;                                              \
   p_arg->notes_attrs = NULL;                                              \
} while(0)
*/

#define P_HIDE_FROM_DDEBUG(p_arg)                                          \
do {                                                                       \
   p_debug_log(P_LKRG_DBG,                                                 \
       "Deleting ddebug information for module [%s]\n",                    \
                                              p_arg->name);                \
   ddebug_remove_module(p_arg->name);                                      \
} while(0)


#ifdef P_LKRG_UNHIDE   // (p_find_me, p_global_modules)

#define P_UNHIDE_FROM_MODULE_LIST(x, y)                                    \
do {                                                                       \
   p_debug_log(P_LKRG_DBG, "Unhiding module [%s | %p]\n",                  \
                                                x->name,x);                \
   list_add_rcu(&x->list, y);                                              \
} while(0)


#define P_UNHIDE_FROM_KOBJ(p_mod,p_kset,p_ktype)                           \
do {                                                                       \
/* struct kobject *p_kobj; */                                              \
   struct module_use *p_use;                                               \
   int p_tmp;                                                              \
   p_debug_log(P_LKRG_DBG, "Creating KOBJ for [%s]\n",                     \
                                              p_mod->name);                \
/* p_kobj = kset_find_obj(p_kset, p_mod->name);                            \
   if (p_kobj) {                                                           \
      p_debug_log(P_LKRG_DBG, "Module [%s] is NOT hidden!\n",              \
                                              p_mod->name);                \
      kobject_put(p_kobj);                                                 \
      return;                                                              \
   } */                                                                    \
   p_mod->mkobj.mod = p_mod;                                               \
   memset(&p_mod->mkobj.kobj, 0, sizeof(p_mod->mkobj.kobj));               \
   p_mod->mkobj.kobj.kset = p_kset;                                        \
   if (kobject_init_and_add(&p_mod->mkobj.kobj, p_ktype, NULL,             \
                                              "%s", p_mod->name)) {        \
      p_debug_log(P_LKRG_DBG, "FAILED :(\n");                              \
      return;                                                              \
   }                                                                       \
   p_mod->holders_dir = kobject_create_and_add("holders",                  \
                                              &p_mod->mkobj.kobj);         \
   if (!p_mod->holders_dir) {                                              \
      p_debug_log(P_LKRG_DBG, "FAILED :(\n");                              \
      return;                                                              \
   }                                                                       \
   if ( (p_tmp = sysfs_create_files(&p_mod->mkobj.kobj,                    \
               (const struct attribute **)&p_mod->modinfo_attrs)) != 0) {  \
      p_debug_log(P_LKRG_DBG, "FAILED :(\n");                              \
      return;                                                              \
   }                                                                       \
   /* add_usage_links() */                                                 \
   list_for_each_entry(p_use, &p_mod->target_list, target_list) {          \
      p_tmp = sysfs_create_link(p_use->target->holders_dir,                \
                            &p_mod->mkobj.kobj, p_mod->name);              \
   }                                                                       \
   /* Created KOBJ for this module is very 'synthetic'.   */               \
   /* During unloading module process, sysfs is heavly    */               \
   /* Influenced. Some of the operations is dangerous if  */               \
   /* Operated on 'syntethic' objects. To avoid crashes   */               \
   /* And limit 'sysfs interaction' let's NULL some of    */               \
   /* Critical 'information' pointers :)                  */               \
   p_mod->notes_attrs = NULL;                                              \
   p_mod->sect_attrs  = NULL;                                              \
   kobject_uevent(&p_mod->mkobj.kobj, KOBJ_ADD);                           \
   p_debug_log(P_LKRG_DBG, "SUCCESS :)\n");                                \
} while(0)

/*
#define P_UNHIDE_FROM_KOBJ(p_mod,p_kobj_parent,p_sect,p_notes)             \
do {                                                                       \
   int p_ret;                                                              \
                                                                           \
   p_debug_log(P_LKRG_DBG, "Reestoring KOBJ[0x%p] for [%s]\n",             \
                                  &p_mod->mkobj.kobj,p_mod->name);         \
   if ( (p_ret = kobject_add(&p_mod->mkobj.kobj, p_kobj_parent,            \
                                                     "p_lkrg")) < 0) {     \
      p_print_log(P_LKRG_INFO, "FAILED to restore KOBJ :(\n");             \
      return;                                                              \
   }                                                                       \
   p_mod->sect_attrs  = p_sect;                                            \
   p_mod->notes_attrs = p_notes;                                           \
} while(0)
*/
#endif


extern struct module *p_find_me;

void p_hide_itself(void);
#ifdef P_LKRG_UNHIDE
void p_unhide_itself(void);
#endif

#endif
