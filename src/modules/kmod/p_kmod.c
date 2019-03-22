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

p_lkrg_global_ctrl_struct p_lkrg_global_ctrl;

struct list_head *p_ddebug_tables = NULL;
struct mutex *p_ddebug_lock = NULL;
struct list_head *p_global_modules = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
struct mutex *p_kernfs_mutex = NULL;
#endif
struct kset **p_module_kset = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
int (*p_ddebug_remove_module_ptr)(const char *p_name) = 0x0;
#endif

int p_kmod_init(void) {

   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_kmod_init>\n");

   p_ddebug_tables    = (struct list_head *)p_kallsyms_lookup_name("ddebug_tables");
   p_ddebug_lock      = (struct mutex *)p_kallsyms_lookup_name("ddebug_lock");
   p_global_modules   = (struct list_head *)p_kallsyms_lookup_name("modules");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   p_kernfs_mutex     = (struct mutex *)p_kallsyms_lookup_name("kernfs_mutex");
#endif
   p_module_kset      = (struct kset **)p_kallsyms_lookup_name("module_kset");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   p_ddebug_remove_module_ptr = (int(*)(const char *))p_kallsyms_lookup_name("ddebug_remove_module");
#endif


   // DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_kmod_init> p_ddebug_tables[0x%lx] p_ddebug_lock[0x%lx] "
                        "module_mutex[0x%lx] p_global_modules[0x%p] "
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
                        "p_ddebug_remove_module_ptr[0x%p]"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
                        "p_kernfs_mutex[0x%p] p_module_kset[0x%p]\n",
#else
                        "p_module_kset[0x%p]\n",
#endif
                                                            (long)p_ddebug_tables,
                                                            (long)p_ddebug_lock,
                                                            (long)&module_mutex,
                                                            p_global_modules,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
                                                            p_ddebug_remove_module_ptr,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
                                                            p_kernfs_mutex,
#endif
                                                            p_module_kset);

   if (!p_global_modules) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't initialize global modules variable :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_kmod_init_out;
   }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
   if (!p_ddebug_remove_module_ptr) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't find 'ddebug_remove_module' function :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_kmod_init_out;
   }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   if (!p_kernfs_mutex) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't find 'kernfs_mutex' variable :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_kmod_init_out;
   }
#endif

   if (!p_module_kset) {
      p_print_log(P_LKRG_ERR,
             "KMOD error! Can't find 'module_kset' variable :( Exiting...\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_kmod_init_out;
   }


p_kmod_init_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_kmod_init> (p_ret => %d)\n",p_ret);

   return p_ret;
}

/*
 * 'module_lock' must be taken by calling function!
 */
unsigned int p_count_modules_from_module_list(void) {

   unsigned int p_cnt = 0x0;
   struct module *p_mod;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_count_modules_from_module_list>\n");

//   mutex_lock(&module_mutex);
   list_for_each_entry(p_mod, p_global_modules, list) {

/*
      if (p_mod->state >= MODULE_STATE_UNFORMED ||
          p_mod->state < MODULE_STATE_LIVE)
         continue;
*/
      if (p_mod->state != MODULE_STATE_LIVE)
         continue;

      if (p_mod == p_find_me)
         continue;

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod))
         continue;

      p_cnt++;
   }
//   mutex_unlock(&module_mutex);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_count_modules_from_module_list> (p_cnt => %d)\n",p_cnt);

   return p_cnt;
}

/*
 * Traverse module list
 *
 * 'module_lock' must be taken by calling function!
 */
int p_list_from_module_list(p_module_list_mem *p_arg, char p_flag) {

   struct module *p_mod;
   int p_ret = P_LKRG_SUCCESS;
   unsigned int p_cnt = 0x0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_list_from_module_list>\n");

//   mutex_lock(&module_mutex);
   list_for_each_entry(p_mod, p_global_modules, list) {
/*
      if (p_mod->state >= MODULE_STATE_UNFORMED ||
          p_mod->state < MODULE_STATE_LIVE)
         continue;
*/
      if (p_mod->state != MODULE_STATE_LIVE)
         continue;

      if (p_mod == p_find_me)
         continue;

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod))
         continue;

      /* Pointer to THIS_MODULE per module */
      p_arg[p_cnt].p_mod = p_mod;
      /* Save module name for that pointer */
      memcpy(p_arg[p_cnt].p_name,p_mod->name,MODULE_NAME_LEN);
      p_arg[p_cnt].p_name[MODULE_NAME_LEN] = 0x0;
      /* Pointer to the module core */
      p_arg[p_cnt].p_module_core = p_module_core(p_mod);
      /* Size of the module core text section */
      p_arg[p_cnt].p_core_text_size = p_core_text_size(p_mod);

      /* Calculate hash from the module's core text section ;) */
      p_arg[p_cnt].p_mod_core_text_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_cnt].p_module_core,
                                                           (unsigned int)p_arg[p_cnt].p_core_text_size);

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             "[%s | %p] module_core[%p | 0x%x] hash[0x%llx]\n",
             p_arg[p_cnt].p_name,p_arg[p_cnt].p_mod,p_arg[p_cnt].p_module_core,
             p_arg[p_cnt].p_core_text_size,p_arg[p_cnt].p_mod_core_text_hash);

      p_cnt++;
   }
//   mutex_unlock(&module_mutex);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_list_from_module_list> (p_ret => %d | p_cnt => %d)\n",p_ret, p_cnt);

   return p_ret;
}

/*
 * 'module_lock' must be taken by calling function!
 */
unsigned int p_count_modules_from_sysfs_kobj(void) {

   struct module *p_mod = NULL;
   struct kset *p_kset = *p_module_kset;
   struct kobject *p_kobj = NULL, *p_tmp_safe = NULL;
   struct module_kobject *p_mk = NULL;
   unsigned int p_cnt = 0x0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_count_modules_from_sysfs_kobj>\n");

   kset_get(p_kset);
   spin_lock(&p_kset->list_lock);
   list_for_each_entry_safe(p_kobj, p_tmp_safe, &p_kset->list, entry) {

      if (!__module_address((unsigned long)p_kobj))
         continue;

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

      if (p_mod == p_find_me) {
         continue;
      }

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod)) {
         continue;
      }

      p_cnt++;
   }
   spin_unlock(&p_kset->list_lock);
   kset_put(p_kset);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_count_modules_from_sysfs_kobj> (p_cnt => %d)\n",p_cnt);

   return p_cnt;
}

/*
 * 'module_lock' must be taken by calling function!
 */
int p_list_from_sysfs_kobj(p_module_kobj_mem *p_arg) {

   struct module *p_mod = NULL;
   struct kset *p_kset = *p_module_kset;
   struct kobject *p_kobj = NULL, *p_tmp_safe = NULL;
   struct module_kobject *p_mk = NULL;
   int p_ret = P_LKRG_SUCCESS;
   unsigned int p_cnt = 0x0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_list_from_sysfs_kobj>\n");

   kset_get(p_kset);
   spin_lock(&p_kset->list_lock);
   list_for_each_entry_safe(p_kobj, p_tmp_safe, &p_kset->list, entry) {

      if (!__module_address((unsigned long)p_kobj))
         continue;

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

      if (p_mod == p_find_me) {
         continue;
      }

      if (!p_module_core(p_mod) || !p_core_text_size(p_mod)) {
         continue;
      }

      /* Save pointer to the 'module_kobject' structure */
      p_arg[p_cnt].p_mk = p_mk;
      /* Save entire 'kobject' for this module */
      memcpy(&p_arg[p_cnt].kobj,p_kobj,sizeof(struct kobject));
      /* Exception */
      memset(&p_arg[p_cnt].kobj.entry,0x0,sizeof(struct list_head)); // module GOING_AWAY trobules ;(
      memset(&p_arg[p_cnt].kobj.kref,0x0,sizeof(struct kref)); // module GOING_AWAY trobules ;(


      /* Pointer to THIS_MODULE per module */
      p_arg[p_cnt].p_mod = p_mod;
      /* Save module name for that pointer */
      memcpy(p_arg[p_cnt].p_name,p_mod->name,MODULE_NAME_LEN);
      p_arg[p_cnt].p_name[MODULE_NAME_LEN] = 0x0;
      /* Pointer to the module core */
      p_arg[p_cnt].p_module_core = p_module_core(p_mod);
      /* Size of the module core text section */
      p_arg[p_cnt].p_core_text_size = p_core_text_size(p_mod);
      /* Calculate hash from the module core text section ;) */
      p_arg[p_cnt].p_mod_core_text_hash = p_lkrg_fast_hash((unsigned char *)p_arg[p_cnt].p_module_core,
                                                           (unsigned int)p_arg[p_cnt].p_core_text_size);

// STRONG_DEBUG
      p_debug_log(P_LKRG_STRONG_DBG,
             "[%s | %p] module_core[%p | 0x%x] hash[0x%llx]\n"
             "module_kobject[%p] KOBJ: name[%s] parent[%p] kset[%p] ktype[%p] sd[%p] refcount[0x%x|%d]\n",
             p_arg[p_cnt].p_name,p_arg[p_cnt].p_mod,p_arg[p_cnt].p_module_core,
             p_arg[p_cnt].p_core_text_size,p_arg[p_cnt].p_mod_core_text_hash,
             p_arg[p_cnt].p_mk,p_arg[p_cnt].kobj.name,p_arg[p_cnt].kobj.parent,
             p_arg[p_cnt].kobj.kset,p_arg[p_cnt].kobj.ktype,p_arg[p_cnt].kobj.sd,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
             p_arg[p_cnt].kobj.kref.refcount.counter,p_arg[p_cnt].kobj.kref.refcount.counter);
#else
             p_arg[p_cnt].kobj.kref.refcount.refs.counter,p_arg[p_cnt].kobj.kref.refcount.refs.counter);
#endif

      p_cnt++;
   }
   spin_unlock(&p_kset->list_lock);
   kset_put(p_kset);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_list_from_sysfs_kobj> (p_cnt => %d)\n",p_cnt);

   return p_ret;
}

/*
 * 'module_lock' must be taken by calling function!
 */
int p_kmod_hash(unsigned int *p_module_list_cnt_arg, p_module_list_mem **p_mlm_tmp,
                unsigned int *p_module_kobj_cnt_arg, p_module_kobj_mem **p_mkm_tmp, char p_flag) {

   int p_ret = P_LKRG_GENERAL_ERROR;
   unsigned int p_module_list_cnt_arg_old = *p_module_list_cnt_arg;
   unsigned int p_module_kobj_cnt_arg_old = *p_module_kobj_cnt_arg;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_kmod_hash>\n");

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
         kzfree(*p_mkm_tmp);
         *p_mkm_tmp = NULL;
      }

      /* First free currently used memory! */
      if (*p_mlm_tmp) {
         kzfree(*p_mlm_tmp);
         *p_mlm_tmp = NULL;
      }
      p_flag = 1;
   }


   /*
    * TODO:
    * Allocation logic should be changed! Should preallocate memory once, and if there
    * there is not enough space, reallocate it multiplying the size, and so on... At some
    * point allocation won't happen at all since we will have enough room to always store
    * all necessary informations.
    */

   if (!p_flag || 1 == p_flag) {

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
                  "<p_kmod_hash> p_mlm_tmp allocated at: %p with size: %zd[0x%zx]\n",
                  *p_mlm_tmp,
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
                  "<p_kmod_hash> p_mkm_tmp allocated at: %p with size: %zd[0x%zx]\n",
                  *p_mkm_tmp,
                  sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                  sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE));
      }

   } else if (p_flag == 2) {

      if (p_module_list_cnt_arg_old < *p_module_list_cnt_arg) {

         /* First free currently used memory! */
         if (*p_mlm_tmp) {
            kzfree(*p_mlm_tmp);
            *p_mlm_tmp = NULL;
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
                     "<p_kmod_hash> p_mlm_tmp allocated at: %p with size: %zd[0x%zx]\n",
                     *p_mlm_tmp,
                     sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE),
                     sizeof(p_module_list_mem) * (*p_module_list_cnt_arg+P_MODULE_BUFFER_RACE));
         }

      } else {
//         printk(KERN_CRIT "p_module_list_cnt_arg_old[%d] *p_module_list_cnt_arg[%d] *p_mlm_tmp[%p]\n",
//                          p_module_list_cnt_arg_old, *p_module_list_cnt_arg, *p_mlm_tmp);
         memset(*p_mlm_tmp,0x0,sizeof(p_module_list_mem) * *p_module_list_cnt_arg);
      }

      if (p_module_kobj_cnt_arg_old < *p_module_kobj_cnt_arg) {

         if (*p_mkm_tmp) {
            kzfree(*p_mkm_tmp);
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
                     "<p_kmod_hash> p_mkm_tmp allocated at: %p with size: %zd[0x%zx]\n",
                     *p_mkm_tmp,
                     sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE),
                     sizeof(p_module_kobj_mem) * (*p_module_kobj_cnt_arg+P_MODULE_BUFFER_RACE));
         }

      } else {
         memset(*p_mkm_tmp,0x0,sizeof(p_module_kobj_mem) * *p_module_kobj_cnt_arg);
      }
   } else {
      *p_mlm_tmp = NULL;
      *p_mkm_tmp = NULL;
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
         kzfree(*p_mlm_tmp);
         *p_mlm_tmp = NULL;
      }
      if (*p_mkm_tmp) {
         kzfree(*p_mkm_tmp);
         *p_mkm_tmp = NULL;
      }
   }

   /*
    * Originally this mutex was taken here. Unfortunately some use cases of this function
    * requires to work under global DB spinlock. Because of that calling function must take
    * 'module_mutex'
    */
//   mutex_unlock(&module_mutex);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_kmod_hash> (%s)\n",(p_ret == P_LKRG_SUCCESS) ? "SUCCESS" : "ERROR");

   return p_ret;
}
