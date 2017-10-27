/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Kernel's modules module notifier 
 *
 * Notes:
 *  - Register notifier function whenever there is any kernel module load/unload activity
 *
 * Timeline:
 *  - Created: 16.II.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */


static int p_module_event_notifier(struct notifier_block *p_this, unsigned long p_event, void *p_kmod);
static void p_module_notifier_wrapper(unsigned long p_event, struct module *p_kmod);

DEFINE_MUTEX(p_module_activity);
struct module *p_module_activity_ptr;

static struct notifier_block p_module_block_notifier = {

   .notifier_call = p_module_event_notifier,
   .next          = NULL,
   .priority      = INT_MAX

};


static void p_module_notifier_wrapper(unsigned long p_event, struct module *p_kmod) {


// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_module_notifier_wrapper>\n");

   if (p_lkrg_global_ctrl.p_block_modules) {
      p_kmod->init = p_block_always;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_module_notifier_wrapper>\n");

   return;
}


/*
 * This function is called when module is load/unloaded
 *
 * Kernel supports following states:
 *
 * 291 enum module_state {
 * 292         MODULE_STATE_LIVE,      // Normal state.
 * 293         MODULE_STATE_COMING,    // Full formed, running module_init.
 * 294         MODULE_STATE_GOING,     // Going away.
 * 295         MODULE_STATE_UNFORMED,  // Still setting it up.
 * 296 };
 */
static int p_module_event_notifier(struct notifier_block *p_this, unsigned long p_event, void *p_kmod) {

   struct module *p_tmp = p_kmod;

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   char *p_mod_strings[] = { "New module is LIVE",
                             "New module is COMING",
                             "Module is GOING AWAY",
                             "New module is UNFORMED yet" };
#endif

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
               "[%ld | %s] "
               "Entering function <p_module_event_notifier> "
               "m[0x%p] hd[0x%p] s[0x%p] n[0x%p]\n",
               p_event,p_mod_strings[p_event],p_tmp,p_tmp->holders_dir,
               p_tmp->sect_attrs,p_tmp->notes_attrs);

   /* Inform validation routine about active module activities... */
   mutex_lock(&p_module_activity);
   p_module_activity_ptr = p_tmp;

// DEBUG
   p_debug_log(P_LKRG_DBG,
          "<p_module_event_notifier> !! Module activity detected [<%s>] %lu: 0x%p\n",p_mod_strings[p_event],p_event,p_kmod);

   /*
    * If module going away, we need to rebuild our database anyway
    * It does not depends on the 'blocking' flag
    */
//   if (p_tmp->state == MODULE_STATE_GOING) { <- Linux kernel bug - might not update state value :(
   if (p_event == MODULE_STATE_GOING) {

      /*
       * Now recalculate modules information in database!
       * Every module must be tracked in the internal database
       * (like hash from .text section) and recalculate global module hashes...
       *
       * Because some module is going to be unloaded from the kernel
       * We must keep in track that information ;)
       */

      /* We are heavly consuming module list here - take 'module_mutex' */
      mutex_lock(&module_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
      /* Hacky way of 'stopping' KOBJs activities */
      mutex_lock(p_kernfs_mutex);
#endif

      /*
       * First, synchronize possible database changes with other LKRG components...
       * We want to be as fast as possible to get this lock! :)
       * Still there is small race condition window, between taking this lock, and
       * verification routine doing that. It might be critical from the perspective
       * of tracking down which modules are currently active in the system and track
       * down this information in database.
       * Imagine situation even we have active 'blocking module' functionality and some
       * random module is going to be unloaded. New event arrives, stack frame for this
       * function is created and before this operation is finished and lock will be taken
       * another CPU might already execute validation routine which will take DB lock
       * before this function will be fast enough to do it after stack frame creation.
       *
       * Don't know if there is any solution for that :)
       *
       */

      /* Let's play... God mode on ;) */
      spin_lock_irqsave(&p_db_lock,p_db_flags);


      /* First free currently used memory! */
      if (p_db.p_module_list_array)
         kzfree(p_db.p_module_list_array);
      if (p_db.p_module_kobj_array)
         kzfree(p_db.p_module_kobj_array);
      /* OK, now recalculate hashes again! */

      while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                        &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array) != P_LKRG_SUCCESS);

      /* Update global module list/kobj hash */
      p_db.p_module_list_hash = p_super_fast_hash((unsigned char *)p_db.p_module_list_array,
                                             (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));
      p_db.p_module_kobj_hash = p_super_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                             (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
      /* We should be fine now! */

      p_print_log(P_LKRG_INFO,"Hash from 'module list' => [0x%x]\n",p_db.p_module_list_hash);
      p_print_log(P_LKRG_INFO,"Hash from 'module kobj(s)' => [0x%x]\n",p_db.p_module_kobj_hash);

      goto p_module_event_notifier_unlock_out;
   }

   if (p_lkrg_global_ctrl.p_block_modules) {
//      if (p_tmp->state == MODULE_STATE_COMING) { <- Linux kernel bug - might not update state value :(
      if (p_event == MODULE_STATE_COMING) {
         /* We are not going to modify DB */
         p_module_notifier_wrapper(p_event,p_tmp);
         goto p_module_event_notifier_activity_out;
      }
   } else {
//      if (p_tmp->state == MODULE_STATE_LIVE) { <- Linux kernel bug - might not update state value :(
      if (p_event == MODULE_STATE_LIVE) {

         /*
          * Now recalculate modules information in database! Since blocking module is disabled
          * every new module must be add to the internal database, hash from .text section calculated
          * and recalculate global module hashes...
          */

         /* We are heavly consuming module list here - take 'module_mutex' */
         mutex_lock(&module_mutex);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
         /* Hacky way of 'stopping' KOBJs activities */
         mutex_lock(p_kernfs_mutex);
#endif

         /*
          * First, synchronize possible database changes with other LKRG components...
          * We want to be as fast as possible to get this lock! :)
          * Still there is small race condition window, between taking this lock, and
          * verification routine doing that. It might be critical from the perspective
          * of tracking down which modules are currently active in the system and track
          * down this information in database.
          * Imagine situation even we have active 'blocking module' functionality and some
          * random module is going to be unloaded. New event arrives, stack frame for this
          * function is created and before this operation is finished and lock will be taken
          * another CPU might already execute validation routine which will take DB lock
          * before this function will be fast enough to do it after stack frame creation.
          *
          * Don't know if there is any solution for that :)
          *
          */
         spin_lock_irqsave(&p_db_lock,p_db_flags);

         /* First free currently used memory! */
         if (p_db.p_module_list_array)
            kzfree(p_db.p_module_list_array);
         if (p_db.p_module_kobj_array)
            kzfree(p_db.p_module_kobj_array);
         /* OK, now recalculate hashes again! */

         while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                        &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array) != P_LKRG_SUCCESS);

         /* Update global module list/kobj hash */
         p_db.p_module_list_hash = p_super_fast_hash((unsigned char *)p_db.p_module_list_array,
                                             (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));
         p_db.p_module_kobj_hash = p_super_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                             (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
         /* We should be fine now! */

         p_print_log(P_LKRG_INFO,"Hash from 'module list' => [0x%x]\n",p_db.p_module_list_hash);
         p_print_log(P_LKRG_INFO,"Hash from 'module kobj(s)' => [0x%x]\n",p_db.p_module_kobj_hash);

         goto p_module_event_notifier_unlock_out;
      }
   }

   goto p_module_event_notifier_activity_out;

p_module_event_notifier_unlock_out:

   /* God mode off ;) */
   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   /* unlock KOBJ activities */
   mutex_unlock(p_kernfs_mutex);
#endif
   /* Release the 'module_mutex' */
   mutex_unlock(&module_mutex);

p_module_event_notifier_activity_out:

   /* Inform validation routine about active module activities... */
   mutex_unlock(&p_module_activity);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_module_event_notifier>\n");

   return NOTIFY_DONE;
}

int p_block_always(void) {

   p_print_log(P_LKRG_CRIT,
          "!! Module insertion blocked (from always!) !!\n");

   return P_LKRG_GENERAL_ERROR;

}

void p_register_module_notifier(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "<p_register_module_notifier> Registering module's noitifier routine\n");

   register_module_notifier(&p_module_block_notifier);

}

void p_deregister_module_notifier(void) {

   unregister_module_notifier(&p_module_block_notifier);
//   printk("Goodbye ;)\n");
}
