/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module
 *
 * Notes:
 *  - Gathers information about loaded kernel modules and tries
 *    to protect them via calculating hashes from their core_text
 *    section.
 *
 * Timeline:
 *  - Created: 09.II.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 * Notes - https://github.com/dgoulet/kjackal/blob/master/src/module.c
 *
 */

#include "../../p_lkrg_main.h"

/* Submodule for 'kmod' module */
#include "p_kmod_notifier.c"


int p_kmod_init(void) {

#if defined(CONFIG_DYNAMIC_DEBUG)
   P_SYM(p_ddebug_tables)    = (struct list_head *)P_SYM(p_kallsyms_lookup_name)("ddebug_tables");
   P_SYM(p_ddebug_lock)      = (struct mutex *)P_SYM(p_kallsyms_lookup_name)("ddebug_lock");
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   P_SYM(p_ddebug_remove_module_ptr) = (int(*)(const char *))P_SYM(p_kallsyms_lookup_name)("ddebug_remove_module");
 #endif
#endif

   P_SYM(p_global_modules)   = (struct list_head *)P_SYM(p_kallsyms_lookup_name)("modules");
   P_SYM(p_module_kset)      = (struct kset **)P_SYM(p_kallsyms_lookup_name)("module_kset");



   // DEBUG
   p_debug_log(P_LKRG_DBG, "<p_kmod_init> "
#if defined(CONFIG_DYNAMIC_DEBUG)
                        "p_ddebug_tables[0x%lx] p_ddebug_lock[0x%lx] "
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
                        "p_ddebug_remove_module_ptr[0x%lx]"
 #endif
#endif
                        "module_mutex[0x%lx] p_global_modules[0x%lx] "
                        "p_module_kset[0x%lx]\n",
#if defined(CONFIG_DYNAMIC_DEBUG)
                                                            (unsigned long)P_SYM(p_ddebug_tables),
                                                            (unsigned long)P_SYM(p_ddebug_lock),
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
                                                            (unsigned long)P_SYM(p_ddebug_remove_module_ptr),
 #endif
#endif
                                                            (long)&module_mutex,
                                                            (unsigned long)P_SYM(p_global_modules),
                                                            (unsigned long)P_SYM(p_module_kset));

   if (!P_SYM(p_global_modules)) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't initialize global modules variable :( Exiting...\n");
      return P_LKRG_GENERAL_ERROR;
   }

#if defined(CONFIG_DYNAMIC_DEBUG)
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   if (!P_SYM(p_ddebug_remove_module_ptr)) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't find 'ddebug_remove_module' function :( Exiting...\n");
      return P_LKRG_GENERAL_ERROR;
   }
 #endif
#endif

   if (!P_SYM(p_module_kset)) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't find 'module_kset' variable :( Exiting...\n");
      return P_LKRG_GENERAL_ERROR;
   }

   return P_LKRG_SUCCESS;
}

/*
 * 'module_lock' must be taken by calling function!
 */
static unsigned int p_count_modules_from_module_list(void) {

   unsigned int p_cnt = 0;
   struct module *p_mod;

   list_for_each_entry(p_mod, P_SYM(p_global_modules), list) {

/*
      if (p_mod->state >= MODULE_STATE_UNFORMED ||
          p_mod->state < MODULE_STATE_LIVE)
         continue;
*/
      if (p_mod->state != MODULE_STATE_LIVE)
         continue;

/*
      if (p_mod == P_SYM(p_find_me))
         continue;
*/

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod))
         continue;

      p_cnt++;
   }

   return p_cnt;
}

/*
 * Traverse module list
 *
 * 'module_lock' must be taken by calling function!
 */
static int p_list_from_module_list(p_module_list_mem *p_arg, char p_flag) {

   struct module *p_mod;
   unsigned int p_cnt = 0;

   list_for_each_entry(p_mod, P_SYM(p_global_modules), list) {
/*
      if (p_mod->state >= MODULE_STATE_UNFORMED ||
          p_mod->state < MODULE_STATE_LIVE)
         continue;
*/
      if (p_mod->state != MODULE_STATE_LIVE)
         continue;

/*
      if (p_mod == P_SYM(p_find_me))
         continue;
*/

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod))
         continue;

      /* Pointer to THIS_MODULE per module */
      p_arg[p_cnt].p_mod = p_mod;
      /* Save module name for that pointer */
      memcpy(p_arg[p_cnt].p_name,p_mod->name,MODULE_NAME_LEN);
      p_arg[p_cnt].p_name[MODULE_NAME_LEN] = 0;
      /* Pointer to the module core */
      p_arg[p_cnt].p_module_core = p_module_core(p_mod);
      /* Size of the module core text section */
      p_arg[p_cnt].p_core_text_size = p_core_text_size(p_mod);

      /* Calculate hash from the module's core text section ;) */
      p_arg[p_cnt].p_mod_core_text_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_cnt].p_module_core,
                                                           (unsigned int)p_arg[p_cnt].p_core_text_size);

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             "[%s | 0x%lx] module_core[0x%lx | 0x%x] hash[0x%llx]\n",
             p_arg[p_cnt].p_name,
             (unsigned long)p_arg[p_cnt].p_mod,
             (unsigned long)p_arg[p_cnt].p_module_core,
             p_arg[p_cnt].p_core_text_size,
             p_arg[p_cnt].p_mod_core_text_hash);

      p_cnt++;
   }

   return P_LKRG_SUCCESS;
}

/*
 * 'module_lock' must be taken by calling function!
 */
unsigned int p_count_modules_from_sysfs_kobj(void) {

   struct module *p_mod = NULL;
   struct kset *p_kset = *P_SYM(p_module_kset);
   struct kobject *p_kobj = NULL, *p_tmp_safe = NULL;
   struct module_kobject *p_mk = NULL;
   unsigned int p_cnt = 0;

   kset_get(p_kset);
   spin_lock(&p_kset->list_lock);
   list_for_each_entry_safe(p_kobj, p_tmp_safe, &p_kset->list, entry) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
      if (!P_SYM(p_module_address)((unsigned long)p_kobj))
         continue;
#else
      if (!__module_address((unsigned long)p_kobj))
         continue;
#endif

      if (!p_kobj->state_initialized || !p_kobj->state_in_sysfs) {
         /* Weirdo state :( */
         continue;
      }

      if (!p_kobj->name) {
         continue;
      }

      p_mk = container_of(p_kobj, struct module_kobject, kobj);
      if (!p_mk) {
         continue;
      }

      p_mod = p_mk->mod;
      if (!p_mod) {
         continue;
      }

      if (p_mod->state != MODULE_STATE_LIVE) {
         continue;
      }

/*
      if (p_mod == P_SYM(p_find_me)) {
         continue;
      }
*/

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod)) {
         continue;
      }

      p_cnt++;
   }
   spin_unlock(&p_kset->list_lock);
   kset_put(p_kset);

   return p_cnt;
}

/*
 * 'module_lock' must be taken by calling function!
 */
static int p_list_from_sysfs_kobj(p_module_kobj_mem *p_arg) {

   struct module *p_mod = NULL;
   struct kset *p_kset = *P_SYM(p_module_kset);
   struct kobject *p_kobj = NULL, *p_tmp_safe = NULL;
   struct module_kobject *p_mk = NULL;
   unsigned int p_cnt = 0;

   kset_get(p_kset);
   spin_lock(&p_kset->list_lock);
   list_for_each_entry_safe(p_kobj, p_tmp_safe, &p_kset->list, entry) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
      if (!P_SYM(p_module_address)((unsigned long)p_kobj))
         continue;
#else
      if (!__module_address((unsigned long)p_kobj))
         continue;
#endif

      if (!p_kobj->state_initialized || !p_kobj->state_in_sysfs) {
         /* Weirdo state :( */
         continue;
      }

      if (!p_kobj->name) {
         continue;
      }

      p_mk = container_of(p_kobj, struct module_kobject, kobj);
      if (!p_mk) {
         continue;
      }

      p_mod = p_mk->mod;
      if (!p_mod) {
         continue;
      }

      if (p_mod->state != MODULE_STATE_LIVE) {
         continue;
      }

/*
      if (p_mod == P_SYM(p_find_me)) {
         continue;
      }
*/

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod)) {
         continue;
      }

      /* Save pointer to the 'module_kobject' structure */
      p_arg[p_cnt].p_mk = p_mk;
      /* Save entire 'kobject' for this module */
      memcpy(&p_arg[p_cnt].kobj,p_kobj,sizeof(struct kobject));
      /* Exception */
      memset(&p_arg[p_cnt].kobj.entry,0,sizeof(struct list_head)); // module GOING_AWAY trobules ;(
      memset(&p_arg[p_cnt].kobj.kref,0,sizeof(struct kref)); // module GOING_AWAY trobules ;(


      /* Pointer to THIS_MODULE per module */
      p_arg[p_cnt].p_mod = p_mod;
      /* Save module name for that pointer */
      memcpy(p_arg[p_cnt].p_name,p_mod->name,MODULE_NAME_LEN);
      p_arg[p_cnt].p_name[MODULE_NAME_LEN] = 0;
      /* Pointer to the module core */
      p_arg[p_cnt].p_module_core = p_module_core(p_mod);
      /* Size of the module core text section */
      p_arg[p_cnt].p_core_text_size = p_core_text_size(p_mod);
      /* Calculate hash from the module core text section ;) */
      p_arg[p_cnt].p_mod_core_text_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_cnt].p_module_core,
                                                           (unsigned int)p_arg[p_cnt].p_core_text_size);

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             "[%s | 0x%lx] module_core[0x%lx | 0x%x] hash[0x%llx]\n"
             "module_kobject[0x%lx] KOBJ: name[%s] parent[0x%lx] "
             "kset[0x%lx] ktype[0x%lx] sd[0x%lx] refcount[0x%x|%d]\n",
             p_arg[p_cnt].p_name,
             (unsigned long)p_arg[p_cnt].p_mod,
             (unsigned long)p_arg[p_cnt].p_module_core,
             p_arg[p_cnt].p_core_text_size,
             p_arg[p_cnt].p_mod_core_text_hash,
             (unsigned long)p_arg[p_cnt].p_mk,
             p_arg[p_cnt].kobj.name,
             (unsigned long)p_arg[p_cnt].kobj.parent,
             (unsigned long)p_arg[p_cnt].kobj.kset,
             (unsigned long)p_arg[p_cnt].kobj.ktype,
             (unsigned long)p_arg[p_cnt].kobj.sd,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
             p_arg[p_cnt].kobj.kref.refcount.counter,
             p_arg[p_cnt].kobj.kref.refcount.counter);
#else
             p_arg[p_cnt].kobj.kref.refcount.refs.counter,
             p_arg[p_cnt].kobj.kref.refcount.refs.counter);
#endif

      p_cnt++;
   }
   spin_unlock(&p_kset->list_lock);
   kset_put(p_kset);

   return P_LKRG_SUCCESS;
}

/*
 * 'module_lock' must be taken by calling function!
 */
int p_kmod_hash(unsigned int *p_module_list_cnt_arg, p_module_list_mem **p_mlm_tmp,
                unsigned int *p_module_kobj_cnt_arg, p_module_kobj_mem **p_mkm_tmp, char p_flag) {

   int p_ret = P_LKRG_GENERAL_ERROR;
   unsigned int p_module_list_cnt_arg_old = *p_module_list_cnt_arg;
   unsigned int p_module_kobj_cnt_arg_old = *p_module_kobj_cnt_arg;

   /*
    * Originally this mutex was taken here. Unfortunately some use cases of this function
    * requires to work under global DB spinlock. Because of that calling function must take
    * 'module_mutex'
    */
//   mutex_lock(&module_mutex);

   *p_module_list_cnt_arg = p_count_modules_from_module_list();
   *p_module_kobj_cnt_arg = p_count_modules_from_sysfs_kobj();

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "[p_kmod_hash] %s => Found %d modules in module list and %d modules in sysfs.\n",
          (*p_module_list_cnt_arg != *p_module_kobj_cnt_arg) ? "DOESN'T MATCH" : "MATCH",
          *p_module_list_cnt_arg,*p_module_kobj_cnt_arg);

   if ( (NULL == *p_mlm_tmp || NULL == *p_mkm_tmp) && p_flag == 2) {
      /*
       * Previous allocation failed :(
       */

      if (*p_mkm_tmp) {
         p_kzfree(*p_mkm_tmp);
         *p_mkm_tmp = NULL;
      }

      /* First free currently used memory! */
      if (*p_mlm_tmp) {
         p_kzfree(*p_mlm_tmp);
         *p_mlm_tmp = NULL;
      }

      if (p_db.p_jump_label.p_mod_mask) {
         kfree(p_db.p_jump_label.p_mod_mask);
         p_db.p_jump_label.p_mod_mask = NULL;
      }

      p_flag = 1;
   }


   /*
    * TODO:
    * Allocation logic should be changed! Should preallocate memory once, and if there
    * there is not enough space, reallocate it multiplying the size, and so on... At some
    * point allocation won't happen at all since we will have enough room to always store
    * all necessary information.
    */

   if (!p_flag || 1 == p_flag) {

      if ( (p_db.p_jump_label.p_mod_mask = kmalloc(BITS_TO_LONGS(*p_module_list_cnt_arg)*sizeof(unsigned long),
                                                   GFP_ATOMIC)) == NULL) {
         /*
          * I should NEVER be here!
          */
         p_ret = P_LKRG_GENERAL_ERROR;
         p_print_log(P_LKRG_CRIT,
                "KMOD HASH kmalloc() error! Can't allocate memory for module bitmask ;[\n");
         goto p_kmod_hash_err;
      }


      /*
       * OK, we now know how many modules we have in the module list
       * in this kernel, let's allocate data here...
       *
       * __GFP_NOFAIL flag will always generate slowpath warn because developers
       * decided to depreciate this flag ;/
       *
       * We are under time-critical pressure. We are going to use emergency pools
       * and we can't accept memory allocation fails. Because __GFP_NOFAIL is not
       * 'safe' flag anymore, we are spinning until allocation succeeds.
       */
      if ( (*p_mlm_tmp = kzalloc(sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE),
                                 GFP_ATOMIC)) == NULL) {
         /*
          * I should NEVER be here!
          */
         p_ret = P_LKRG_GENERAL_ERROR;
         p_print_log(P_LKRG_CRIT,
                "KMOD HASH kzalloc() error! Can't allocate memory for module list ;[\n");
         goto p_kmod_hash_err;
      }
      // STRONG_DEBUG
        else {
           p_debug_log(P_LKRG_STRONG_DBG,
                  "<p_kmod_hash> p_mlm_tmp allocated at: 0x%lx with size: %zd[0x%zx]\n",
                  (unsigned long)*p_mlm_tmp,
                  sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE),
                  sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE));
      }

      /*
       * OK, we now know how many modules we have in the sysfs kset/kobject list
       * in this kernel, let's allocate data here...
       *
       * __GFP_NOFAIL flag will always generate slowpath warn because developers
       * decided to depreciate this flag ;/
       *
       * We are under time-critical pressure. We are going to use emergency pools
       * and we can't accept memory allocation fails. Because __GFP_NOFAIL is not
       * 'safe' flag anymore, we are spinning until allocation succeeds.
       */
      if ( (*p_mkm_tmp = kzalloc(sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                                 GFP_ATOMIC)) == NULL) {
         /*
          * I should NEVER be here!
          */
         p_ret = P_LKRG_GENERAL_ERROR;
         p_print_log(P_LKRG_CRIT,
                "KMOD HASH kzalloc() error! Can't allocate memory for kobj list;[\n");
         goto p_kmod_hash_err;
      }
      // STRONG_DEBUG
        else {
           p_debug_log(P_LKRG_STRONG_DBG,
                  "<p_kmod_hash> p_mkm_tmp allocated at: 0x%lx with size: %zd[0x%zx]\n",
                  (unsigned long)*p_mkm_tmp,
                  sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                  sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE));
      }

   } else if (p_flag == 2) {

      if (p_module_list_cnt_arg_old < *p_module_list_cnt_arg) {

         /* First free currently used memory! */
         if (*p_mlm_tmp) {
            p_kzfree(*p_mlm_tmp);
            *p_mlm_tmp = NULL;
         }

         if (p_db.p_jump_label.p_mod_mask) {
            kfree(p_db.p_jump_label.p_mod_mask);
            p_db.p_jump_label.p_mod_mask = NULL;
         }

         if ( (p_db.p_jump_label.p_mod_mask = kmalloc(BITS_TO_LONGS(*p_module_list_cnt_arg)*sizeof(unsigned long),
                                                      GFP_ATOMIC)) == NULL) {
            /*
             * I should NEVER be here!
             */
            p_ret = P_LKRG_GENERAL_ERROR;
            p_print_log(P_LKRG_CRIT,
                   "KMOD HASH kmalloc() error! Can't allocate memory for module bitmask ;[\n");
            goto p_kmod_hash_err;
         }

         /*
          * OK, we now know how many modules we have in the module list
          * in this kernel, let's allocate data here...
          *
          * __GFP_NOFAIL flag will always generate slowpath warn because developers
          * decided to depreciate this flag ;/
          *
          * We are under time-critical pressure. We are going to use emergency pools
          * and we can't accept memory allocation fails. Because __GFP_NOFAIL is not
          * 'safe' flag anymore, we are spinning until allocation succeeds.
          */
         if ( (*p_mlm_tmp = kzalloc(sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE),
                                    GFP_ATOMIC)) == NULL) {
            /*
             * I should NEVER be here!
             */
            p_ret = P_LKRG_GENERAL_ERROR;
            p_print_log(P_LKRG_CRIT,
                   "KMOD HASH kzalloc() error! Can't allocate memory for module list ;[\n");
            goto p_kmod_hash_err;
         }
      // STRONG_DEBUG
           else {
//              p_print_log(P_LKRG_CRIT,
              p_debug_log(P_LKRG_STRONG_DBG,
                     "<p_kmod_hash> p_mlm_tmp allocated at: 0x%lx with size: %zd[0x%zx]\n",
                     (unsigned long)*p_mlm_tmp,
                     sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE),
                     sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE));
         }

      } else {
//         printk(KERN_CRIT "p_module_list_cnt_arg_old[%d] *p_module_list_cnt_arg[%d] *p_mlm_tmp[0x%lx]\n",
//                          p_module_list_cnt_arg_old, *p_module_list_cnt_arg, (unsigned long)*p_mlm_tmp);
         memset(*p_mlm_tmp,0,sizeof(p_module_list_mem) * *p_module_list_cnt_arg);
      }

      if (p_module_kobj_cnt_arg_old < *p_module_kobj_cnt_arg) {

         if (*p_mkm_tmp) {
            p_kzfree(*p_mkm_tmp);
            *p_mkm_tmp = NULL;
         }

         /*
          * OK, we now know how many modules we have in the sysfs kset/kobject list
          * in this kernel, let's allocate data here...
          *
          * __GFP_NOFAIL flag will always generate slowpath warn because developers
          * decided to depreciate this flag ;/
          *
          * We are under time-critical pressure. We are going to use emergency pools
          * and we can't accept memory allocation fails. Because __GFP_NOFAIL is not
          * 'safe' flag anymore, we are spinning until allocation succeeds.
          */
         if ( (*p_mkm_tmp = kzalloc(sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                                    GFP_ATOMIC)) == NULL) {
            /*
             * I should NEVER be here!
             */
            p_ret = P_LKRG_GENERAL_ERROR;
            p_print_log(P_LKRG_CRIT,
                   "KMOD HASH kzalloc() error! Can't allocate memory for kobj list;[\n");
            goto p_kmod_hash_err;
         }
      // STRONG_DEBUG
           else {
              p_debug_log(P_LKRG_STRONG_DBG,
                     "<p_kmod_hash> p_mkm_tmp allocated at: 0x%lx with size: %zd[0x%zx]\n",
                     (unsigned long)*p_mkm_tmp,
                     sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                     sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE));
         }

      } else {
         memset(*p_mkm_tmp,0,sizeof(p_module_kobj_mem) * *p_module_kobj_cnt_arg);
      }
   } else {

      if (*p_mlm_tmp) {
         p_kzfree(*p_mlm_tmp);
         *p_mlm_tmp = NULL;
      }
      if (*p_mkm_tmp) {
         p_kzfree(*p_mkm_tmp);
         *p_mkm_tmp = NULL;
      }
      if (p_db.p_jump_label.p_mod_mask) {
         kfree(p_db.p_jump_label.p_mod_mask);
         p_db.p_jump_label.p_mod_mask = NULL;
      }
      goto p_kmod_hash_err;
   }

   if ( (p_ret = p_list_from_module_list(*p_mlm_tmp, p_flag)) != P_LKRG_SUCCESS) {
      /*
       * I should NEVER be here!
       */
      p_print_log(P_LKRG_CRIT,
             "KMOD HASH error! Can't allocate memory during dumping modules from module list ;[\n");
      goto p_kmod_hash_err;
   }

   p_list_from_sysfs_kobj(*p_mkm_tmp);

   p_ret = P_LKRG_SUCCESS;

p_kmod_hash_err:

   if (p_ret != P_LKRG_SUCCESS) {
      if (*p_mlm_tmp) {
         p_kzfree(*p_mlm_tmp);
         *p_mlm_tmp = NULL;
      }
      if (*p_mkm_tmp) {
         p_kzfree(*p_mkm_tmp);
         *p_mkm_tmp = NULL;
      }
      if (p_db.p_jump_label.p_mod_mask) {
         kfree(p_db.p_jump_label.p_mod_mask);
         p_db.p_jump_label.p_mod_mask = NULL;
      }
   }

   /*
    * Originally this mutex was taken here. Unfortunately some use cases of this function
    * requires to work under global DB spinlock. Because of that calling function must take
    * 'module_mutex'
    */
//   mutex_unlock(&module_mutex);

   return p_ret;
}
