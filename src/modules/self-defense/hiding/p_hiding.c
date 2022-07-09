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

#include "../../../p_lkrg_main.h"

/*
struct kobject            *p_find_kobj_parent;
struct module_sect_attrs  *p_find_sect_attrs;
struct module_notes_attrs *p_find_notes_attrs;
*/


void p_hide_itself(void) {

   if (P_CTRL(p_hide_lkrg)) {
      p_print_log(P_LOG_WATCH, "Module is already hidden");
      return;
   }

/*
   p_find_kobj_parent = p_find_me->mkobj.kobj.parent;
   p_find_sect_attrs  = p_find_me->sect_attrs;
   p_find_notes_attrs = p_find_me->notes_attrs;
*/

   /* We are heavily consuming module list here - take 'module_mutex' */
   mutex_lock(P_SYM(p_module_mutex));

   P_HIDE_FROM_MODULE_LIST(P_SYM(p_find_me));
   P_HIDE_FROM_KOBJ(P_SYM(p_find_me));
#if defined(CONFIG_DYNAMIC_DEBUG)
   P_HIDE_FROM_DDEBUG(P_SYM(p_find_me));
#endif

   /* OK, now recalculate hashes again! */
   while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                     &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array, 0x2) != P_LKRG_SUCCESS)
      schedule();

   /* Update global module list/kobj hash */
   p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                          (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));

   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
   /* We should be fine now! */

   P_CTRL(p_hide_lkrg) = 1;

   /* Release the 'module_mutex' */
   mutex_unlock(P_SYM(p_module_mutex));
}

#ifdef P_LKRG_UNHIDE
void p_unhide_itself(void) {

   struct module     *p_tmp_mod    = P_GLOBAL_TO_MODULE(P_SYM(p_modules));
   struct kset       *p_tmp_kset   = p_tmp_mod->mkobj.kobj.kset;
   struct kobj_type  *p_tmp_ktype  = (struct kobj_type *)((void*)p_tmp_mod->mkobj.kobj.ktype);

   if (!P_CTRL(p_hide_lkrg)) {
      p_print_log(P_LOG_WATCH, "Module is already unhidden (visible)");
      return;
   }

   /* We are heavily consuming module list here - take 'module_mutex' */
   mutex_lock(P_SYM(p_module_mutex));

   P_UNHIDE_FROM_MODULE_LIST(P_SYM(p_find_me),P_SYM(p_modules));
   P_UNHIDE_FROM_KOBJ(P_SYM(p_find_me),p_tmp_kset,p_tmp_ktype);

//   P_UNHIDE_FROM_KOBJ(P_SYM(p_find_me),p_find_kobj_parent,
//                      p_find_sect_attrs,p_find_notes_attrs);

   /* OK, now recalculate hashes again! */
   while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                     &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array, 0x2) != P_LKRG_SUCCESS)
      schedule();

   /* Update global module list/kobj hash */
   p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                          (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));

   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
   /* We should be fine now! */

   P_CTRL(p_hide_lkrg) = 0;

p_unhide_itself_exit:
   /* Release the 'module_mutex' */
   mutex_unlock(P_SYM(p_module_mutex));
}
#endif
