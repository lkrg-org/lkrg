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


static int p_block_always(void) {

   p_print_log(P_LOG_WATCH, "Module loading blocked");

   return P_LKRG_GENERAL_ERROR;

}

static void p_module_notifier_wrapper(unsigned long p_event, struct module *p_kmod) {

   if (P_CTRL(p_block_modules)) {
      p_print_log(P_LOG_ALERT, "BLOCK: Module: Loading of module name %s", p_kmod->name);
      p_kmod->init = p_block_always;
   }

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

   static const char * const p_mod_strings[] = {
                             "New module is LIVE",
                             "New module is COMING",
                             "Module is GOING AWAY",
                             "New module is UNFORMED yet" };

// STRONG_DEBUG
   p_debug_log(P_LOG_FLOOD,
               "[%ld | %s | %s] Entering function <p_module_event_notifier> m[0x%lx] hd[0x%lx] s[0x%lx] n[0x%lx]",
               p_event,
               p_mod_strings[p_event],
               p_tmp->name,
               (unsigned long)p_tmp,
               (unsigned long)p_tmp->holders_dir,
               (unsigned long)p_tmp->sect_attrs,
               (unsigned long)p_tmp->notes_attrs);

   /* Inform validation routine about active module activities... */
   mutex_lock(&p_module_activity);
   p_module_activity_ptr = p_tmp;

// DEBUG
   p_debug_log(P_LOG_DEBUG,
          "<p_module_event_notifier> !! Module activity detected [<%s>] %lu: 0x%lx",
          p_mod_strings[p_event],
          p_event,
          (unsigned long)p_kmod);

   /*
    * If module going away, we need to rebuild our database anyway
    * It does not depends on the 'blocking' flag
    */
//   if (p_tmp->state == MODULE_STATE_GOING) { <- Linux kernel bug - might not update state value :(
   if (p_event == MODULE_STATE_GOING) {

      p_read_cpu_lock();
      on_each_cpu(p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
      p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
      p_read_cpu_unlock();

      /*
       * Now recalculate modules information in database!
       * Every module must be tracked in the internal database
       * (like hash from .text section) and recalculate global module hashes...
       *
       * Because some module is going to be unloaded from the kernel
       * We must keep in track that information ;)
       */
      p_verify_module_going(p_tmp);

      p_text_section_lock();
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
//      spin_lock_irqsave(&p_db_lock,p_db_flags);
      spin_lock(&p_db_lock);

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

      p_print_log(P_LOG_WATCH,"Hash from 'module list' => [0x%llx]",p_db.p_module_list_hash);
      p_print_log(P_LOG_WATCH,"Hash from 'module kobj(s)' => [0x%llx]",p_db.p_module_kobj_hash);

      if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
         p_print_log(P_LOG_FAULT, "Can't recalculate hash of a module (%s)", p_mod_strings[p_event]);
      }
      p_print_log(P_LOG_WATCH,"Hash from '_stext' => [0x%llx]",p_db.kernel_stext.p_hash);

      goto p_module_event_notifier_unlock_out;
   }

   if (P_CTRL(p_block_modules) && p_tmp != P_SYM(p_find_me)) {
//      if (p_tmp->state == MODULE_STATE_COMING) { <- Linux kernel bug - might not update state value :(
      if (p_event == MODULE_STATE_COMING) {
         /* We are not going to modify DB */
         p_module_notifier_wrapper(p_event,p_tmp);
         goto p_module_event_notifier_activity_out;
      }
   } else {
//      if (p_tmp->state == MODULE_STATE_LIVE) { <- Linux kernel bug - might not update state value :(
      if (p_event == MODULE_STATE_LIVE) {

         p_read_cpu_lock();
         on_each_cpu(p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
         p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);
         p_read_cpu_unlock();

         /*
          * Now recalculate modules information in database! Since blocking module is disabled
          * every new module must be add to the internal database, hash from .text section calculated
          * and recalculate global module hashes...
          */
         p_verify_module_live(p_tmp);

         p_text_section_lock();
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
//         spin_lock_irqsave(&p_db_lock,p_db_flags);
         spin_lock(&p_db_lock);

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

         p_print_log(P_LOG_WATCH,"Hash from 'module list' => [0x%llx]",p_db.p_module_list_hash);
         p_print_log(P_LOG_WATCH,"Hash from 'module kobj(s)' => [0x%llx]",p_db.p_module_kobj_hash);

         if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
            p_print_log(P_LOG_FAULT, "Can't recalculate hash of a module (%s)", p_mod_strings[p_event]);
         }
         p_print_log(P_LOG_WATCH,"Hash from '_stext' => [0x%llx]",p_db.kernel_stext.p_hash);

         goto p_module_event_notifier_unlock_out;
      }
   }

   goto p_module_event_notifier_activity_out;

p_module_event_notifier_unlock_out:

   /* God mode off ;) */
//   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
   spin_unlock(&p_db_lock);
   p_text_section_unlock();

p_module_event_notifier_activity_out:

   /* Inform validation routine about active module activities... */
   mutex_unlock(&p_module_activity);

   return NOTIFY_DONE;
}

void p_verify_module_live(struct module *p_mod) {

#if P_OVL_OVERRIDE_SYNC_MODE
   if (p_ovl_override_sync_kretprobe_state) {
      /* We do not need to do anything for now */
      return;
   }

   if (!strcmp(p_mod->name,"overlay") || !strcmp(p_mod->name,"overlay2")) {
      unsigned int p_tmp_val;

      /*
       * OK, we must try to hook 'ovl_create_or_link' function.
       * Otherwise LKRG will be incompatible with docker.
       *
       * First, we would need to synchronize with LKRG integrity feature.
       */
      p_tmp_val = P_CTRL(p_kint_validate);
      p_lkrg_open_rw();
      P_CTRL(p_kint_validate) = 0;
      p_lkrg_close_rw();
      /* Try to install the hook */
      if (p_install_ovl_override_sync_hook(1)) {
         p_print_log(P_LOG_FAULT,
                "OverlayFS is being loaded but LKRG can't hook '" P_OVL_OVERRIDE_SYNC_FUNC "'. "
                "It is very likely that LKRG will produce false positives. Please reload LKRG.");
      }
      /* Done */
      p_lkrg_open_rw();
      P_CTRL(p_kint_validate) = p_tmp_val;
      p_lkrg_close_rw();
   }
#endif
}

void p_verify_module_going(struct module *p_mod) {

#if P_OVL_OVERRIDE_SYNC_MODE
   if (!p_ovl_override_sync_kretprobe_state) {
      /* We do not need to do anything for now */
      return;
   }

   if (!strcmp(p_mod->name,"overlay") || !strcmp(p_mod->name,"overlay2")) {
      unsigned int p_tmp_val;

      /*
       * OK, we must try to remove our hook @ 'ovl_create_or_link' function.
       *
       * First, we would need to synchronize with LKRG integrity feature.
       */
      p_tmp_val = P_CTRL(p_kint_validate);
      p_lkrg_open_rw();
      P_CTRL(p_kint_validate) = 0;
      p_lkrg_close_rw();
      /* Try to uninstall the hook */
      p_uninstall_ovl_override_sync_hook();
      p_reinit_ovl_override_sync_kretprobe();
      /* Done */
      p_lkrg_open_rw();
      P_CTRL(p_kint_validate) = p_tmp_val;
      p_lkrg_close_rw();
   }
#endif

}

void p_register_module_notifier(void) {

// STRONG_DEBUG
   p_debug_log(P_LOG_FLOOD,
          "<p_register_module_notifier> Registering module's noitifier routine");

   register_module_notifier(&p_module_block_notifier);

}

void p_deregister_module_notifier(void) {

   unregister_module_notifier(&p_module_block_notifier);

   if (p_db.p_module_list_array) {
      p_kzfree(p_db.p_module_list_array);
      p_db.p_module_list_array = NULL;
   }
   if (p_db.p_module_kobj_array) {
      p_kzfree(p_db.p_module_kobj_array);
      p_db.p_module_kobj_array = NULL;
   }
   if (p_db.p_jump_label.p_mod_mask) {
      kfree(p_db.p_jump_label.p_mod_mask);
      p_db.p_jump_label.p_mod_mask = NULL;
   }
}
