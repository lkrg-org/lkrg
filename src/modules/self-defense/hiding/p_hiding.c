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

struct module             *p_find_me = THIS_MODULE;
/*
struct kobject            *p_find_kobj_parent;
struct module_sect_attrs  *p_find_sect_attrs;
struct module_notes_attrs *p_find_notes_attrs;
*/


void p_hide_itself(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_hide_itself>\n");

   if (!p_lkrg_global_ctrl.p_unhide_module) {
      p_print_log(P_LKRG_WARN,
             "Module is already hidden!\n");
      goto p_hide_itself_out;
   }

/*
   p_find_kobj_parent = p_find_me->mkobj.kobj.parent;
   p_find_sect_attrs  = p_find_me->sect_attrs;
   p_find_notes_attrs = p_find_me->notes_attrs;
*/

   P_HIDE_FROM_MODULE_LIST(p_find_me);
   P_HIDE_FROM_KOBJ(p_find_me);
   P_HIDE_FROM_DDEBUG(p_find_me);

   p_lkrg_global_ctrl.p_unhide_module = 0x0;

p_hide_itself_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_hide_itself>\n");

   return;
}

#ifdef P_LKRG_UNHIDE
void p_unhide_itself(void) {

   /* Dead function - used only during development process */
   struct module     *p_tmp_mod    = P_GLOBAL_TO_MODULE(p_global_modules);
   struct kset       *p_tmp_kset   = p_tmp_mod->mkobj.kobj.kset;
   struct kobj_type  *p_tmp_ktype  = p_tmp_mod->mkobj.kobj.ktype;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_unhide_itself>\n");

   if (p_lkrg_global_ctrl.p_unhide_module) {
      p_print_log(P_LKRG_WARN,
             "Module is already unhidden (visible)!\n");
      goto p_unhide_itself_out;
   }

   P_UNHIDE_FROM_MODULE_LIST(p_find_me,p_global_modules);
   P_UNHIDE_FROM_KOBJ(p_find_me,p_tmp_kset,p_tmp_ktype);

//   P_UNHIDE_FROM_KOBJ(p_find_me,p_find_kobj_parent,
//                      p_find_sect_attrs,p_find_notes_attrs);

   p_lkrg_global_ctrl.p_unhide_module = 0x1;

p_unhide_itself_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_unhide_itself>\n");

   return;
}
#endif
