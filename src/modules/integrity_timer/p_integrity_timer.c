/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Integrity timer module
 *
 * Notes:
 *  - Periodically check critical system hashes using timer
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

/*
 * Local timer for integrity checks...
 */
struct timer_list p_timer;

unsigned int p_time_stamp = 15; /* timeout in seconds */
/* God mode variables ;) */
DEFINE_SPINLOCK(p_db_lock);
unsigned long p_db_flags;
unsigned int p_manual = 0;

/* kmem_cache for offloding WQ */
struct kmem_cache *p_offload_cache = NULL;


static void p_offload_cache_zero(void *p_arg) {

   struct work_struct *p_struct = p_arg;

   memset(p_struct, 0, sizeof(struct work_struct));
}

int p_offload_cache_init(void) {

   if ( (p_offload_cache = kmem_cache_create("p_offload_cache", sizeof(struct work_struct),
                                             0, SLAB_HWCACHE_ALIGN, p_offload_cache_zero)) == NULL) {
      p_print_log(P_LKRG_ERR, "kmem_cache_create() for offloading error! :(\n");
      return -ENOMEM;
   }

   return P_LKRG_SUCCESS;
}

void p_offload_cache_delete(void) {

   flush_workqueue(system_unbound_wq);
   if (p_offload_cache) {
      kmem_cache_destroy(p_offload_cache);
      p_offload_cache = NULL;
   }
}

void p_integrity_timer(void) {

   p_timer.expires    = jiffies + P_CTRL(p_interval)*HZ;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
   p_timer.data       = 1;
   p_timer.function   = p_offload_work;
   init_timer(&p_timer);
#else
   timer_setup(&p_timer, p_offload_work, 0);
#endif
   add_timer(&p_timer);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
void p_offload_work(unsigned long p_timer) {
#else
void p_offload_work(struct timer_list *p_timer) {
#endif

   struct work_struct *p_worker;

   p_debug_log(P_LKRG_STRONG_DBG,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
          "p_timer => %ld\n",p_timer);
#else
          "p_timer => %lx\n",(unsigned long)p_timer);
#endif

   while ( (p_worker = p_alloc_offload()) == NULL); // Should never be NULL
   INIT_WORK(p_worker, p_check_integrity);
   /* schedule for execution */
   queue_work(system_unbound_wq, p_worker);
   if (p_timer)
      p_integrity_timer();
}


void p_check_integrity(struct work_struct *p_work) {

   /* temporary hash variable */
   uint64_t p_tmp_hash;
   /* per CPU temporary data */
   p_CPU_metadata_hash_mem *p_tmp_cpus = NULL;
   p_cpu_info p_tmp_cpu_info;
   /* Linux Kernel Modules integrity */
   unsigned int p_module_list_nr_tmp; // Count by walk through the list first
   unsigned int p_module_kobj_nr_tmp; // Count by walk through the list first
   p_module_list_mem *p_module_list_tmp = NULL;
   p_module_kobj_mem *p_module_kobj_tmp = NULL;
   char p_mod_bad_nr = 0;
   /* Are we compromised ? */
   unsigned int p_hack_check = 0;
   /* Module syncing temporary pointer */
   struct module *p_tmp_mod;
   unsigned int p_tmp = 0;
   int p_ret;

   if (!P_CTRL(p_kint_validate) || (!p_manual && P_CTRL(p_kint_validate) == 1))
      goto p_check_integrity_tasks;

   /*
    * First allocate temporary buffer for per CPU data. Number of possible CPUs
    * is per kernel compilation. Hot plug-in/off won't change that value so it is
    * safe to preallocate buffer here - before lock and before recounting CPUs info.
    */

   /*
    * __GFP_NOFAIL flag will always generate slowpath warn because developers
    * decided to depreciate this flag ;/
    */
//   while ( (p_tmp_cpus = kzalloc(sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids,
//                              GFP_KERNEL | GFP_ATOMIC | GFP_NOFS | __GFP_REPEAT)) == NULL);

   /*
    * We are in the off-loaded WQ context. We can sleep here (because we must be able to
    * take 'mutex' lock which is 'sleeping' lock), so it is not strictly time-critical code.
    * This allocation is made before we take 'spinlock' for internal database (and before
    * we take 'sleeping mutext lock' but it doesn't count for now) we are allowed to
    * make 'slowpath' memory allocation - don't need to use emergency pools.
    *
    * Emergency pools will be consumed in 'kmod' module (because we will be under 'spinlock'
    * timing pressure).
    */
   while ( (p_tmp_cpus = kzalloc(sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids,
                                             GFP_KERNEL | GFP_NOFS | __GFP_REPEAT)) == NULL);



   /* Find information about current CPUs in the system */
   p_get_cpus(&p_tmp_cpu_info);
   if (p_cmp_cpus(&p_db.p_cpu,&p_tmp_cpu_info)) {
      p_print_log(P_LKRG_WARN,
             "!!! INTEGRITY WARNING: Using CPU number from original database !!!\n");
   }

   /*
    * Check which core did we lock and do not send IPI to yourself.
    * It will cause internal bug in smp_call_function_single() which
    * uses get_cpu() internally. Core must be unlocked before calling
    * this function!
    */
//   p_tmp_cpuid = smp_processor_id();

   /*
    * Checking all online CPUs critical data
    */
   get_online_cpus();

//   for_each_present_cpu(p_tmp) {
   //for_each_online_cpu(p_tmp) {
//      if (cpu_online(p_tmp)) {
//         if (p_tmp_cpuid != p_tmp) {
//printk(KERN_INFO "smp_call_function_single() for cpu[%d]\n",p_tmp);
            /*
             * smp_call_function_single() internally 'locks' the execution core.
             * This means you should not call this function with IRQ disabled.
             * It will generate warnings/OOPS - it is not documented but this is
             * how this function reacts.
             */
            //smp_call_function_single(p_tmp,p_dump_CPU_metadata,p_tmp_cpus,true);
//printk(KERN_INFO "smp_call_function_single() -> DONE\n");
//         }
//      }
   //}


  /*
   * There is an undesirable situation in SMP Linux machines when sending
   * IPI via the smp_call_function_single() API...
   *
   * ... more technical details about it can be found here:
   *  *) http://blog.pi3.com.pl/?p=549
   *  *) http://lists.openwall.net/linux-kernel/2016/09/21/68
   *
   * on_each_cpu() might mitigate this problem a bit because has extra
   * self-balancing code for performance reasons.
   */
   on_each_cpu(p_dump_CPU_metadata,p_tmp_cpus,true);


   /*
    * OK, so now get the same information for currently locked core!
    */
//   p_dump_CPU_metadata(p_tmp_cpus); // no return value

   /* Now we are safe to disable IRQs on current core */

   p_tmp_hash = hash_from_CPU_data(p_tmp_cpus);
   put_online_cpus();

   p_text_section_lock();

   /*
    * Memory allocation may fail... let's loop here!
    */
   while( (p_ret = p_kmod_hash(&p_module_list_nr_tmp,&p_module_list_tmp,
                               &p_module_kobj_nr_tmp,&p_module_kobj_tmp, 0x0)) != P_LKRG_SUCCESS) {
      if (p_ret == P_LKRG_KMOD_DUMP_RACE) {
         p_print_log(P_LKRG_ERR,
                "Function <p_check_integrity> won race with module activity thread... We need to cancel this context! :(\n");
         goto p_check_integrity_cancel;
      }
      p_print_log(P_LKRG_ERR,
             "Function <p_check_integrity> - p_kmod_hash() failed! Memory problems... :(\n");
      schedule();
   }
/*
   p_text_section_unlock();
*/

   spin_lock_irqsave(&p_db_lock,p_db_flags);
//   spin_lock(&p_db_lock);

   if (p_db.p_CPU_metadata_hashes != p_tmp_hash) {
      /* I'm hacked! ;( */
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! HASHES FROM CPUs METADATA IS DIFFERENT- it is [0x%llx] and should be [0x%llx] !!!\n",
                                                               p_tmp_hash,p_db.p_CPU_metadata_hashes);
      P_KINT_IF_ACCEPT(p_db.p_CPU_metadata_hashes,
                       p_tmp_hash,
                       p_hack_check);
   }

   p_print_log(P_LKRG_INFO,"Hash from CPUs metadata => [0x%llx]\n",p_tmp_hash);

   /*
    * Checking memory block:
    * "___ex_table"
    */
   if (p_db.kernel_ex_table.p_addr && p_db.kernel_ex_table.p_hash) {
      p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_ex_table.p_addr,
                                    (unsigned int)p_db.kernel_ex_table.p_size);

      if (p_db.kernel_ex_table.p_hash != p_tmp_hash) {
         /* I'm hacked! ;( */
         p_print_log(P_LKRG_CRIT,
                "ALERT !!! EXCEPTION TABLE HASH IS DIFFERENT - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                                  p_tmp_hash,p_db.kernel_ex_table.p_hash);
         P_KINT_IF_ACCEPT(p_db.kernel_ex_table.p_hash,
                          p_tmp_hash,
                          p_hack_check);
      }

      p_print_log(P_LKRG_INFO,"Hash from kernel exception table => [0x%llx]\n",p_tmp_hash);
   }

   /*
    * Checking memory block:
    * "_stext"
    */
   p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_stext.p_addr,
                                 (unsigned int)p_db.kernel_stext.p_size);

   if (p_db.kernel_stext.p_hash != p_tmp_hash) {
#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
      char *p_str1 = (unsigned char *)p_db.kernel_stext.p_addr;
      char *p_str2 = (unsigned char *)p_db.kernel_stext_copy;
      char p_eh_buf[0x100];
#endif
      /* We detected core kernel .text corruption - we are hacked and can't recover */
      /* I'm hacked! ;( */
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! _STEXT MEMORY BLOCK HASH IS DIFFERENT - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                            p_tmp_hash,p_db.kernel_stext.p_hash);
#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
      for (p_tmp = 0; p_tmp < p_db.kernel_stext.p_size; p_tmp++) {
         if (p_str2[p_tmp] != p_str1[p_tmp]) {
            sprint_symbol_no_offset(p_eh_buf,(unsigned long)((unsigned long)p_db.kernel_stext.p_addr+(unsigned long)p_tmp));
            printk(KERN_CRIT "copy[0x%x] vs now[0x%x] offset[%d | 0x%x] symbol[%s]\n",
                   p_str2[p_tmp],
                   p_str1[p_tmp],
                   p_tmp,
                   p_tmp,
                   p_eh_buf);
         }
      }
#endif
      P_KINT_IF_ACCEPT(p_db.kernel_stext.p_hash,
                       p_tmp_hash,
                       p_hack_check);
   }

   p_print_log(P_LKRG_INFO,"Hash from _stext memory block => [0x%llx]\n",p_tmp_hash);

   /*
    * Checking memory block:
    * "_rodata"
    */
   if (p_db.kernel_rodata.p_addr && p_db.kernel_rodata.p_hash) {
#if !defined(CONFIG_GRKERNSEC)
      p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_rodata.p_addr,
                                    (unsigned int)p_db.kernel_rodata.p_size);
#else
      p_tmp_hash = 0xFFFFFFFF;
#endif

      if (p_db.kernel_rodata.p_hash != p_tmp_hash) {
         /* I'm hacked! ;( */
         p_print_log(P_LKRG_CRIT,
                "ALERT !!! _RODATA MEMORY BLOCK HASH IS DIFFERENT - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                                  p_tmp_hash,p_db.kernel_rodata.p_hash);
         P_KINT_IF_ACCEPT(p_db.kernel_rodata.p_hash,
                          p_tmp_hash,
                          p_hack_check);
      }

      p_print_log(P_LKRG_INFO,"Hash from _rodata memory block => [0x%llx]\n",p_tmp_hash);
   }

   /*
    * Checking memory block:
    * "__iommu_table"
    */
   if (p_db.kernel_iommu_table.p_addr && p_db.kernel_iommu_table.p_hash) {
#ifdef P_LKRG_IOMMU_HASH_ENABLED
      p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_iommu_table.p_addr,
                                    (unsigned int)p_db.kernel_iommu_table.p_size);
#else
      p_tmp_hash = 0xFFFFFFFF;
#endif

      if (p_db.kernel_iommu_table.p_hash != p_tmp_hash) {
         /* I'm hacked! ;( */
         p_print_log(P_LKRG_CRIT,
                "ALERT !!! IOMMU TABLE HASH IS DIFFERENT - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                                  p_tmp_hash,p_db.kernel_iommu_table.p_hash);
         P_KINT_IF_ACCEPT(p_db.kernel_iommu_table.p_hash,
                          p_tmp_hash,
                          p_hack_check);
      }

      p_print_log(P_LKRG_INFO,"Hash from IOMMU table => [0x%llx]\n",p_tmp_hash);
   }

/*
   unsigned int p_module_list_nr_tmp; // Count by walk through the list first
   unsigned int p_module_kobj_nr_tmp; // Count by walk through the list first
   p_module_list_mem *p_module_list_tmp;
   p_module_kobj_mem *p_module_kobj_tmp;
*/

   /*
    * Checking this kernel modules integrity.
    */

   /*
    * Memory allocation may fail... let's loop here!
    */
//   while(p_kmod_hash(&p_module_list_nr_tmp,&p_module_list_tmp,
//                     &p_module_kobj_nr_tmp,&p_module_kobj_tmp) != P_LKRG_SUCCESS);

/*
   if (p_kmod_hash(&p_module_list_nr_tmp,&p_module_list_tmp,
                   &p_module_kobj_nr_tmp,&p_module_kobj_tmp) != P_LKRG_SUCCESS) {
      printk(P_LKRG_PRINT P_LKRG_SIGNATURE
         "<p_check_integrity> p_kmod_hash() ERROR! - skipping integrity check of modules!\n");
//      return P_LKRG_GENERAL_ERROR;
   }
*/

   /*
    * If we enter this block it means we've found module which is
    * not registered in module list or sysfs.
    * Let's find out where we miss module and print which one
    *
    * TODO: dump as much info about this module as possible e.g.
    * core-dump image, ddebug_table information, symbol table, etc.
    */
   if (p_module_list_nr_tmp != p_module_kobj_nr_tmp) {
      unsigned int p_tmp_cnt,p_tmp_diff = 0;
      char p_tmp_flag,p_tmp_flag_cnt = 0;

      p_mod_bad_nr++;
      if (p_module_list_nr_tmp < p_module_kobj_nr_tmp) {
         /*
          * If we found less modules in module list than KOBJs
          * Most likely module tries to hide, we can make preassumption
          * system might be hacked.
          *
          * NOTE: We should have been able to log this module in the loading
          *       stage by notifier!
          */
         P_KINT_HACK_I(p_hack_check);

         p_tmp_diff = p_module_kobj_nr_tmp - p_module_list_nr_tmp;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_module_kobj_nr_tmp;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_module_list_nr_tmp; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_module_kobj_tmp[p_tmp_hash].p_mod == p_module_list_tmp[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in KOBJ list but not in module list... */
               p_tmp_flag_cnt++;

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Hidden[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_module_kobj_tmp[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        P_KINT_HACK_D(p_hack_check);
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in module list[%d] than in KOBJ[%d]\n",
                              p_tmp_diff,
                              p_module_list_nr_tmp,
                              p_module_kobj_nr_tmp);
                        p_print_log(P_LKRG_INFO,
                              "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_kobj_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                              p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                              p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Lost module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_module_kobj_tmp[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              P_KINT_HACK_D(p_hack_check);
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in module list[%d] than in KOBJ[%d]\n",
                                    p_tmp_diff,
                                    p_module_list_nr_tmp,
                                    p_module_kobj_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_kobj_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                    p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              P_KINT_HACK_D(p_hack_check);
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in module list[%d] than in KOBJ[%d]\n",
                                    p_tmp_diff,
                                    p_module_list_nr_tmp,
                                    p_module_kobj_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_kobj_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                    p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");
                              // TODO: Dump module
                           }
                        } else {
                           p_print_log(P_LKRG_CRIT,
                                  "ALERT !!! FOUND LESS[%d] MODULES IN MODULE LIST[%d] THAN IN KOBJ[%d]\n",
                                  p_tmp_diff,
                                  p_module_list_nr_tmp,
                                  p_module_kobj_nr_tmp);
                           /* Let's dump information about 'hidden' module */
                           p_print_log(P_LKRG_CRIT,
                              "HIDDEN MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_kobj_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                              p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                              p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_CRIT,
                                  "!! MOST LIKELY SYSTEM IS HACKED - MODULE WILL BE DUMPED !! **\n");

                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE HACKED!
                           // TODO: Dump module
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_module_kobj_tmp[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           P_KINT_HACK_D(p_hack_check);
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in module list[%d] than in KOBJ[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_module_kobj_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_kobj_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                 p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           P_KINT_HACK_D(p_hack_check);
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in module list[%d] than in KOBJ[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_module_kobj_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_kobj_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                 p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");
                           // TODO: Dump module
                        }
                     } else {
                           p_print_log(P_LKRG_CRIT,
                                  "ALERT !!! FOUND LESS[%d] MODULES IN MODULE LIST[%d] THAN IN KOBJ[%d]\n",
                                  p_tmp_diff,
                                  p_module_list_nr_tmp,
                                  p_module_kobj_nr_tmp);
                           /* Let's dump information about 'hidden' module */
                           p_print_log(P_LKRG_CRIT,
                              "HIDDEN MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_kobj_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                              p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                              p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_CRIT,
                                  "!! MOST LIKELY SYSTEM IS HACKED - MODULE WILL BE DUMPED !! **\n");

                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE HACKED!
                           // TODO: Dump module
                     }
                  }
               } else {
                  p_print_log(P_LKRG_CRIT,
                        "ALERT !!! FOUND LESS[%d] MODULES IN MODULE LIST[%d] THAN IN KOBJ[%d]\n",
                        p_tmp_diff,
                        p_module_list_nr_tmp,
                        p_module_kobj_nr_tmp);
                  /* Let's dump information about 'hidden' module */
                  p_print_log(P_LKRG_CRIT,
                        "HIDDEN MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                        p_module_kobj_tmp[p_tmp_hash].p_name,
                        (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                        (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                        p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                        p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                  p_print_log(P_LKRG_CRIT,
                         "!! MOST LIKELY SYSTEM IS HACKED - MODULE WILL BE DUMPED !! **\n");

                  // Dynamic module blocking is disabled so this situation shouldn't happen
                  // MOST LIKELY WE ARE HACKED!
                  // TODO: Dump module
               }
            }
         }
         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }
      } else if (p_module_kobj_nr_tmp < p_module_list_nr_tmp) {
        /*
         * This is strange behaviour. Most of the malicious modules don't remove them from KOBJ
         * Just from module list. If any remove themselves from the KOBJ most likely they also
         * Removed themselves from the module list as well. I would not make assumption system is
         * Somehow compromised but for sure something very strange happened! That's why we should
         * Inform about that!
         */

         p_tmp_diff = p_module_list_nr_tmp - p_module_kobj_nr_tmp;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_module_list_nr_tmp;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_module_kobj_nr_tmp; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_module_list_tmp[p_tmp_hash].p_mod == p_module_kobj_tmp[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in MODULE LIST list but not in KOBJ... */
               p_tmp_flag_cnt++;

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Hidden[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_module_list_tmp[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                              p_tmp_diff,
                              p_module_kobj_nr_tmp,
                              p_module_list_nr_tmp);
                        p_print_log(P_LKRG_INFO,
                              "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_list_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                              p_module_list_tmp[p_tmp_hash].p_core_text_size,
                              p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Lost module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_module_list_tmp[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                    p_tmp_diff,
                                    p_module_kobj_nr_tmp,
                                    p_module_list_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_list_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                    p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                    p_tmp_diff,
                                    p_module_kobj_nr_tmp,
                                    p_module_list_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_list_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                    p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");
                              // TODO: Dump module
                           }
                        } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_kobj_nr_tmp,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_WARN,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in module list but not in KOBJs (system is stable).\n");
                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE NOT HACKED :)
                           // TODO: Dump module
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_module_list_tmp[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_kobj_nr_tmp,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_kobj_nr_tmp,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");

                           // TODO: Dump module
                        }
                     } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_kobj_nr_tmp,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_WARN,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in module list but not in KOBJs (system is stable).\n");

                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE NOT HACKED :)
                           // TODO: Dump module
                     }
                  }
               } else {
                  p_print_log(P_LKRG_WARN,
                        "Found less[%d] modules in KOBJ[%d] than in module list[%d]\n",
                        p_tmp_diff,
                        p_module_kobj_nr_tmp,
                        p_module_list_nr_tmp);
                  p_print_log(P_LKRG_WARN,
                        "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                        p_module_list_tmp[p_tmp_hash].p_name,
                        (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                        (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                        p_module_list_tmp[p_tmp_hash].p_core_text_size,
                        p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                  p_print_log(P_LKRG_WARN,
                        "Strange behaviour detected - module was found in module list but not in KOBJs (system is stable).\n");

                  // Dynamic module blocking is disabled so this situation shouldn't happen
                  // MOST LIKELY WE ARE NOT HACKED :)
                  // TODO: Dump module
               }
            }
         }
         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }

      } else {
         p_print_log(P_LKRG_CRIT,
                "I should never be here!... something went wrong ;( module list[%d] KOBJ[%d]\n",
                p_module_list_nr_tmp,p_module_kobj_nr_tmp);
      }
   }


   /*
    * We found as many modules in module list as in sysfs
    * Let's validate if our database has the same information as we gathered now
    *
    */


   /*
    * If we enter this block number of modules in module list and sysfs are the same.
    * Unfortunately we have not the same number of modules in database module list
    * than currently in the system!
    * Let's find out which module we missing and print some information about it.
    *
    * TODO: dump as much info about this module as possible e.g.
    * core-dump image, ddebug_table information, symbol table, etc.
    */
   if (p_module_list_nr_tmp != p_db.p_module_list_nr) {
      unsigned int p_tmp_cnt,p_tmp_diff = 0;
      char p_tmp_flag,p_tmp_flag_cnt = 0;

      p_mod_bad_nr++;
      if (p_module_list_nr_tmp < p_db.p_module_list_nr) {
         /*
          * We "lost" module which we didn't register somehow.
          * It might happen regardless of notifier informing us on any
          * module related activities.
          *
          * I would not make assumption system is somehow compromised
          * but we should inform about that.
          *
          * It might happen when verification routine wins
          * the race with module notification routine of acquiring
          * module mutexes. In that case, notification routine will
          * wait until this verification context unlocks mutexes.
          */

         p_tmp_diff = p_db.p_module_list_nr - p_module_list_nr_tmp;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_db.p_module_list_nr;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_module_list_nr_tmp; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_db.p_module_list_array[p_tmp_hash].p_mod == p_module_list_tmp[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in DB module list but not in current module list... */
               p_tmp_flag_cnt++;

               // TODO: Module disappeared and we didn't notice it! We shouldn't dump it because
               // most likely module doesn't exists anymore...
               // But we can try to poke that page where modules used to be to find out scratches
               // of information about it (e.g. name? symbols table?)

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Lost[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_db.p_module_list_array[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                              p_tmp_diff,
                              p_module_list_nr_tmp,
                              p_db.p_module_list_nr);
                        p_print_log(P_LKRG_INFO,
                              "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_db.p_module_list_array[p_tmp_hash].p_name,
                              (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                              (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                              p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                              p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Lost module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_db.p_module_list_array[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                    p_tmp_diff,
                                    p_module_list_nr_tmp,
                                    p_db.p_module_list_nr);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_db.p_module_list_array[p_tmp_hash].p_name,
                                    (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                    (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                    p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                    p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                    p_tmp_diff,
                                    p_module_list_nr_tmp,
                                    p_db.p_module_list_nr);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_db.p_module_list_array[p_tmp_hash].p_name,
                                    (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                    (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                    p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                    p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");

                              // TODO: Dirty dump module - from the memory scratches if possible
                           }
                        } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_db.p_module_list_nr);
                           p_print_log(P_LKRG_WARN,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_list_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in DB but not in OS (system is stable).\n");

                           // Did NOT find it in the system via official API...
                           // TODO: Dirty dump module - from the memory scratches if possible
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_db.p_module_list_array[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_db.p_module_list_nr);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_list_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_db.p_module_list_nr);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_list_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");
                           // TODO: Dirty dump module - from the memory scratches if possible
                        }
                     } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in current system in module list [%d] than in DB module list[%d]\n",
                                 p_tmp_diff,
                                 p_module_list_nr_tmp,
                                 p_db.p_module_list_nr);
                           p_print_log(P_LKRG_WARN,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_list_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_list_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_list_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_list_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in DB but not in OS (system is stable).\n");

                           // Did NOT find it in the system via official API...
                           // TODO: Dirty dump module - from the memory scratches if possible
                     }
                  }
               }
            }
         }
         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }
      } else if (p_db.p_module_list_nr < p_module_list_nr_tmp) {
         /*
          * This is weird situation as well. Notifier should inform us
          * whenever new module arrives and we rebuild database.
          *
          * It might happen when verification routine wins
          * the race with module notification routine of acquiring
          * module mutexes. In that case, notification routine will
          * wait until this verification context unlocks mutexes.
          *
          * I would not make assumption system is somehow compromised
          * but we should inform about that!
          */

         p_tmp_diff = p_module_list_nr_tmp - p_db.p_module_list_nr;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_module_list_nr_tmp;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_db.p_module_list_nr; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_module_list_tmp[p_tmp_hash].p_mod == p_db.p_module_list_array[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in current module list but not in DB module list... */
               p_tmp_flag_cnt++;

               // TODO: Dump module

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Extra[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_module_list_tmp[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in DB module list [%d] than in current module list[%d]\n",
                              p_tmp_diff,
                              p_db.p_module_list_nr,
                              p_module_list_nr_tmp);
                        p_print_log(P_LKRG_INFO,
                              "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_list_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                              p_module_list_tmp[p_tmp_hash].p_core_text_size,
                              p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Extra module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_module_list_tmp[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in DB module list [%d] than in current module list[%d]\n",
                                    p_tmp_diff,
                                    p_db.p_module_list_nr,
                                    p_module_list_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_list_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                    p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in DB module list [%d] than in current module list[%d]\n",
                                    p_tmp_diff,
                                    p_db.p_module_list_nr,
                                    p_module_list_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_list_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                    p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");

                              // TODO: Dump module
                           }
                        } else {
                           p_print_log(P_LKRG_CRIT,
                                 "ALERT !!! FOUND LESS[%d] MODULES IN DB IN MODULE LIST[%d] THAN IN CURRENT MODULE LIST[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_list_nr,
                                 p_module_list_nr_tmp);
                           /* Let's dump information about 'hidden' module */
                           p_print_log(P_LKRG_CRIT,
                              "EXTRA MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_list_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                              p_module_list_tmp[p_tmp_hash].p_core_text_size,
                              p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_CRIT,
                                  "!! MOST LIKELY SYSTEM IS HACKED - MODULE WILL BE DUMPED !! **\n");

                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE HACKED!
                           // TODO: Dump module
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_module_list_tmp[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in DB module list [%d] than in current module list[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_list_nr,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in DB module list [%d] than in current module list[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_list_nr,
                                 p_module_list_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_list_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                                 p_module_list_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");
                           // TODO: Dump module
                        }
                     } else {
                        p_print_log(P_LKRG_CRIT,
                              "ALERT !!! FOUND LESS[%d] MODULES IN DB IN MODULE LIST[%d] THAN IN CURRENT MODULE LIST[%d]\n",
                              p_tmp_diff,
                              p_db.p_module_list_nr,
                              p_module_list_nr_tmp);
                        /* Let's dump information about 'hidden' module */
                        p_print_log(P_LKRG_CRIT,
                           "EXTRA MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                           p_module_list_tmp[p_tmp_hash].p_name,
                           (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                           (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                           p_module_list_tmp[p_tmp_hash].p_core_text_size,
                           p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);

                        // Did NOT find it in the system via official API...
                        // MOST LIKELY WE ARE HACKED!
                        // TODO: Dump module
                     }
                  }
               } else {
                 p_print_log(P_LKRG_CRIT,
                       "ALERT !!! FOUND LESS[%d] MODULES IN DB IN MODULE LIST[%d] THAN IN CURRENT MODULE LIST[%d]\n",
                       p_tmp_diff,
                       p_db.p_module_list_nr,
                       p_module_list_nr_tmp);
                /* Let's dump information about 'hidden' module */
                p_print_log(P_LKRG_CRIT,
                      "EXTRA MODULE:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                      p_module_list_tmp[p_tmp_hash].p_name,
                      (unsigned long)p_module_list_tmp[p_tmp_hash].p_mod,
                      (unsigned long)p_module_list_tmp[p_tmp_hash].p_module_core,
                      p_module_list_tmp[p_tmp_hash].p_core_text_size,
                      p_module_list_tmp[p_tmp_hash].p_mod_core_text_hash);
                  p_print_log(P_LKRG_CRIT,
                         "!! MOST LIKELY SYSTEM IS HACKED - MODULE WILL BE DUMPED !! **\n");

                  // Dynamic module blocking is disabled so this situation shouldn't happen
                  // MOST LIKELY WE ARE HACKED!
                  // TODO: Dump module
               }
            }
         }

         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }
      } else {
         p_print_log(P_LKRG_CRIT,
                "I should never be here!... something went wrong ;( module list[%d] DB module list[%d]\n",
                p_module_list_nr_tmp,p_db.p_module_list_nr);
      }
   }


   /*
    * If we enter this block number of modules in module list and sysfs are the same.
    * Unfortunately we have not the same number of modules in database KOBJ
    * than currently in the system!
    * Let's find out which module we missing and print some information about it.
    *
    * TODO: dump as much info about this module as possible e.g.
    * core-dump image, ddebug_table information, symbol table, etc.
    */
   if (p_module_kobj_nr_tmp != p_db.p_module_kobj_nr) {
      unsigned int p_tmp_cnt,p_tmp_diff = 0;
      char p_tmp_flag,p_tmp_flag_cnt = 0;

      p_mod_bad_nr++;
      if (p_module_kobj_nr_tmp < p_db.p_module_kobj_nr) {
         /*
          * This is weird situation as well. Notifier should inform us
          * whenever new module arrives and we rebuild database.
          *
          * It might happen when verification routine wins
          * the race with module notification routine of acquiring
          * module mutexes. In that case, notification routine will
          * wait until this verification context unlocks mutexes.
          *
          * I would not make assumption system is somehow compromised
          * but we should inform about that!
          */

         p_tmp_diff = p_db.p_module_kobj_nr - p_module_kobj_nr_tmp;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_db.p_module_kobj_nr;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_module_kobj_nr_tmp; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_db.p_module_kobj_array[p_tmp_hash].p_mod == p_module_kobj_tmp[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in KOBJ DB but not in the current KOBJ list... */
               p_tmp_flag_cnt++;

               // TODO: Module disappeared and we didn't notice it! We shouldn't dump it because
               // most likely module doesn't exists anymore...
               // But we can try to poke that page where modules used to be to find out scratches
               // of information about it (e.g. name? symbols table?)

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Lost[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_db.p_module_kobj_array[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                               p_tmp_diff,
                               p_module_kobj_nr_tmp,
                               p_db.p_module_kobj_nr);
                        p_print_log(P_LKRG_INFO,
                              "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_db.p_module_kobj_array[p_tmp_hash].p_name,
                              (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                              (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                              p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                              p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Lost module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_db.p_module_kobj_array[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                                     p_tmp_diff,
                                     p_module_kobj_nr_tmp,
                                     p_db.p_module_kobj_nr);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_db.p_module_kobj_array[p_tmp_hash].p_name,
                                    (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                    (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                                    p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                                    p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                                     p_tmp_diff,
                                     p_module_kobj_nr_tmp,
                                     p_db.p_module_kobj_nr);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_db.p_module_kobj_array[p_tmp_hash].p_name,
                                    (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                    (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                                    p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                                    p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");

                              // TODO: Dirty dump module - from the memory scratches if possible
                           }
                        } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                                  p_tmp_diff,
                                  p_module_kobj_nr_tmp,
                                  p_db.p_module_kobj_nr);
                           p_print_log(P_LKRG_WARN,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_kobj_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in DB but not in OS (system is stable).\n");
                           // Did NOT find it in the system via official API...
                           // TODO: Dirty dump module - from the memory scratches if possible
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_db.p_module_kobj_array[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                                  p_tmp_diff,
                                  p_module_kobj_nr_tmp,
                                  p_db.p_module_kobj_nr);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_kobj_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                                  p_tmp_diff,
                                  p_module_kobj_nr_tmp,
                                  p_db.p_module_kobj_nr);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_db.p_module_kobj_array[p_tmp_hash].p_name,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                                 (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                                 p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Lost module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");
                           // TODO: Dirty dump module - from the memory scratches if possible
                        }
                     } else {
                        p_print_log(P_LKRG_WARN,
                              "Found less[%d] modules in current system in KOBJ [%d] than in DB KOBJ[%d]\n",
                               p_tmp_diff,
                               p_module_kobj_nr_tmp,
                               p_db.p_module_kobj_nr);
                        p_print_log(P_LKRG_WARN,
                              "Lost module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_db.p_module_kobj_array[p_tmp_hash].p_name,
                              (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_mod,
                              (unsigned long)p_db.p_module_kobj_array[p_tmp_hash].p_module_core,
                              p_db.p_module_kobj_array[p_tmp_hash].p_core_text_size,
                              p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_WARN,
                               "Strange behaviour detected - module was found in DB but not in OS (system is stable).\n");
                        // Did NOT find it in the system via official API...
                        // TODO: Dirty dump module - from the memory scratches if possible
                     }
                  }
               }
            }
         }
         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }
      } else if (p_db.p_module_kobj_nr < p_module_kobj_nr_tmp) {
         /*
          * This is weird situation as well. Notifier should inform us
          * whenever new module arrives and we rebuild database.
          *
          * It might happen when verification routine wins
          * the race with module notification routine of acquiring
          * module mutexes. In that case, notification routine will
          * wait until this verification context unlocks mutexes.
          *
          * I would not make assumption system is somehow compromised
          * but we should inform about that!
          */

         p_tmp_diff = p_module_kobj_nr_tmp - p_db.p_module_kobj_nr;

         for (p_tmp_flag = 0, p_tmp_hash = 0; p_tmp_hash < p_module_kobj_nr_tmp;
                                                               p_tmp_flag = 0, p_tmp_hash++) {
            for (p_tmp_cnt = 0; p_tmp_cnt < p_db.p_module_kobj_nr; p_tmp_cnt++) {
               /* Is module on both lists? */
               if (p_module_kobj_tmp[p_tmp_hash].p_mod == p_db.p_module_kobj_array[p_tmp_cnt].p_mod) {
                  p_tmp_flag = 1;
                  break;
               }
            }
            /* Did we find missing module? */
            if (!p_tmp_flag) {
               /* OK we found which module is in the current KOBJ list but not in KOBJ DB... */
               p_tmp_flag_cnt++;

               // TODO: Dump module

               if (!P_CTRL(p_block_modules)) {
                  /* Maybe we have sleeping module activity event ? */
                  if (mutex_is_locked(&p_module_activity)) {
                     // STRONG_DEBUG
                     p_debug_log(P_LKRG_STRONG_DBG,
                                "Extra[0x%lx] p_module_activity_ptr[0x%lx]\n",
                                (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                (unsigned long)p_module_activity_ptr);
                     if (p_module_kobj_tmp[p_tmp_hash].p_mod == p_module_activity_ptr) {
                        p_print_log(P_LKRG_INFO,
                              "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                              p_tmp_diff,
                              p_db.p_module_kobj_nr,
                              p_module_kobj_nr_tmp);
                        p_print_log(P_LKRG_INFO,
                              "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_kobj_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                              p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                              p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_INFO,
                                    "Extra module is the same as on-going module activity events (system is stable).\n");
                     } else {
                        p_tmp_mod = find_module(p_module_kobj_tmp[p_tmp_hash].p_name);
                        if (p_tmp_mod) {
                           if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                                    p_tmp_diff,
                                    p_db.p_module_kobj_nr,
                                    p_module_kobj_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_kobj_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                    p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                    (p_tmp_mod->state == 1) ? "COMING" :
                                    (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                    (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                           } else {
                              p_print_log(P_LKRG_INFO,
                                    "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                                    p_tmp_diff,
                                    p_db.p_module_kobj_nr,
                                    p_module_kobj_nr_tmp);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                    p_module_kobj_tmp[p_tmp_hash].p_name,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                    (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                    p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                    p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                              p_print_log(P_LKRG_INFO,
                                    "Extra module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                    "identified through the official API. Most likely race condition appeared when system "
                                    "was rebuilding database (system is stable).\n");

                              // TODO: Dump module
                           }
                        } else {
                           p_print_log(P_LKRG_WARN,
                                 "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_kobj_nr,
                                 p_module_kobj_nr_tmp);
                           p_print_log(P_LKRG_WARN,
                                 "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_kobj_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                 p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_WARN,
                                  "Strange behaviour detected - module was found in DB KOBJs but not in OS (system is stable).\n");
                           // Did NOT find it in the system via official API...
                           // MOST LIKELY WE ARE NOT HACKED :)
                           // TODO: Dump module
                        }
                     }
                  } else {
                     p_tmp_mod = find_module(p_module_kobj_tmp[p_tmp_hash].p_name);
                     if (p_tmp_mod) {
                        if (p_tmp_mod->state != MODULE_STATE_LIVE) {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_kobj_nr,
                                 p_module_kobj_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_kobj_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                 p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module is not in the 'LIVE' state but in [%s] state (system is stable).\n",
                                 (p_tmp_mod->state == 1) ? "COMING" :
                                 (p_tmp_mod->state == 2) ? "GOING AWAY" :
                                 (p_tmp_mod->state == 3) ? "COMING" : "UNKNOWN!");
                        } else {
                           p_print_log(P_LKRG_INFO,
                                 "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                                 p_tmp_diff,
                                 p_db.p_module_kobj_nr,
                                 p_module_kobj_nr_tmp);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                                 p_module_kobj_tmp[p_tmp_hash].p_name,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                                 (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                                 p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                                 p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                           p_print_log(P_LKRG_INFO,
                                 "Extra module has 'live' state but 'block_modules' is disabled. Module was correctly "
                                 "identified through the official API. Most likely race condition appeared when system "
                                 "was rebuilding database (system is stable).\n");
                           // TODO: Dump module
                        }
                     } else {
                        p_print_log(P_LKRG_WARN,
                              "Found less[%d] modules in DB in KOBJ [%d] than in current KOBJ[%d]\n",
                              p_tmp_diff,
                              p_db.p_module_kobj_nr,
                              p_module_kobj_nr_tmp);
                        p_print_log(P_LKRG_WARN,
                              "Extra module:\nname[%s] module at addr[0x%lx] module core[0x%lx] with size[0x%x] hash[0x%llx]\n",
                              p_module_kobj_tmp[p_tmp_hash].p_name,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_mod,
                              (unsigned long)p_module_kobj_tmp[p_tmp_hash].p_module_core,
                              p_module_kobj_tmp[p_tmp_hash].p_core_text_size,
                              p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash);
                        p_print_log(P_LKRG_WARN,
                               "Strange behaviour detected - module was found in DB KOBJs but not in OS (system is stable).\n");

                        // Did NOT find it in the system via official API...
                        // MOST LIKELY WE ARE NOT HACKED :)
                        // TODO: Dump module
                     }
                  }
               }
            }
         }
         /* We should never be here... we found more mismatched modules than expected */
         if (p_tmp_diff != p_tmp_flag_cnt) {
            p_print_log(P_LKRG_ERR,
               "We found more[%d] missing modules than expected[%d]... something went wrong ;(\n",
               p_tmp_flag_cnt,p_tmp_diff);
         }
      } else {
         p_print_log(P_LKRG_CRIT,
                "I should never be here!... something went wrong ;( module list[%d] DB module list[%d]\n",
                p_module_list_nr_tmp,p_db.p_module_list_nr);
      }
   }


/*   if ( (p_module_list_nr_tmp != p_module_kobj_nr_tmp) || (p_module_list_nr_tmp != p_db.p_module_list_nr)
        || (p_module_kobj_nr_tmp != p_db.p_module_kobj_nr) ) {
      printk(P_LKRG_PRINT P_LKRG_SIGNATURE
             "ALERT !!! MODULE NUMBERS ARE INCONSISTENT! IN DB: LIST[%d] KOBJ[%d], found LIST[%d], KOBJ[%d]\n",
             p_db.p_module_list_nr,p_db.p_module_kobj_nr,p_module_list_nr_tmp,p_module_kobj_nr_tmp);
      p_hack_check++;

      // TODO: Find missing module and DUMP as much info as possible about that!

   }
*/


   p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_module_list_tmp,
                                 (unsigned int)p_module_list_nr_tmp * sizeof(p_module_list_mem));

   p_print_log(P_LKRG_INFO,"Hash from 'module list' => [0x%llx]\n",p_tmp_hash);

   if (p_tmp_hash != p_db.p_module_list_hash) {
      unsigned int p_tmp_cnt,p_local_hack_check = 0;

      for (p_tmp = 0; p_tmp < p_db.p_module_list_nr; p_tmp++) {
         for (p_tmp_cnt = 0; p_tmp_cnt < p_module_list_nr_tmp; p_tmp_cnt++) {
            if (p_db.p_module_list_array[p_tmp].p_mod == p_module_list_tmp[p_tmp_cnt].p_mod) {
               if (p_db.p_module_list_array[p_tmp].p_mod_core_text_hash != p_module_list_tmp[p_tmp_cnt].p_mod_core_text_hash) {
                  /* I'm hacked! ;( */
                  p_print_log(P_LKRG_CRIT,
                              "ALERT !!! MODULE'S <%s> HASH IS DIFFERENT it is [0x%llx] and should be [0x%llx] !!!\n",
                              p_module_list_tmp[p_tmp_cnt].p_name,
                              p_module_list_tmp[p_tmp_cnt].p_mod_core_text_hash,
                              p_db.p_module_list_array[p_tmp_cnt].p_mod_core_text_hash);
                  P_KINT_IF_ACCEPT(p_db.p_module_list_array[p_tmp_cnt].p_mod_core_text_hash,
                                   p_module_list_tmp[p_tmp_cnt].p_mod_core_text_hash,
                                   p_hack_check);
                  p_local_hack_check++;
               }
            }
         }
      }
/*
      if (!p_local_hack_check) {
         p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                                    (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));

         if (p_tmp_hash != p_db.p_module_list_hash) {
            p_local_hack_check = 1;
         }
      }
*/
      /*
       * OK, we know hash will be different if there is inconsistency in the number
       * of tracked / discovered modules in module list and/or in sysfs (KOBJs)
       */
      if (p_local_hack_check) {
         if (!p_mod_bad_nr) {

            /* Maybe we have sleeping module activity event ? */
            if (mutex_is_locked(&p_module_activity)) {
                  P_KINT_HACK_D(p_hack_check);
                  p_print_log(P_LKRG_INFO,
                              "Unhandled on-going module activity events detected. "
                              "Activity changed module list consistency (system is stable).\n");
            } else {
               p_print_log(P_LKRG_CRIT,
                      "ALERT !!! MODULE LIST HASH IS DIFFERENT !!! - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                                             p_tmp_hash,p_db.p_module_list_hash);
               P_KINT_HACK_I(p_hack_check);
            }
         }
      }

   }

   p_tmp_hash = p_lkrg_fast_hash((unsigned char *)p_module_kobj_tmp,
                                 (unsigned int)p_module_kobj_nr_tmp * sizeof(p_module_kobj_mem));

   p_print_log(P_LKRG_INFO,"Hash from 'module kobj(s)' => [0x%llx]\n",p_tmp_hash);

   if (p_tmp_hash != p_db.p_module_kobj_hash) {

      /*
       * OK, we know hash will be different if there is inconsistency in the number
       * of tracked / discovered modules in module list and/or in sysfs (KOBJs)
       */
      if (!p_mod_bad_nr) {
         /* Maybe we have sleeping module activity event ? */
         if (mutex_is_locked(&p_module_activity)) {
               p_print_log(P_LKRG_INFO,
                           "Unhandled on-going module activity events detected. "
                           "Activity changed KOBJs consistency (system is stable).\n");
         } else {
            p_print_log(P_LKRG_CRIT,
                   "ALERT !!! MODULE KOBJ HASH IS DIFFERENT !!! - it is [0x%llx] and should be [0x%llx] !!!\n",
                                                                          p_tmp_hash,p_db.p_module_kobj_hash);
            P_KINT_HACK_I(p_hack_check);
         }
      }

      for (p_tmp_hash = 0; p_tmp_hash < p_db.p_module_kobj_nr; p_tmp_hash++) {
         unsigned int p_tmp_cnt;
         for (p_tmp_cnt = 0; p_tmp_cnt < p_module_kobj_nr_tmp; p_tmp_cnt++) {
            if (p_db.p_module_kobj_array[p_tmp_hash].p_mod == p_module_kobj_tmp[p_tmp_cnt].p_mod)
               if (p_db.p_module_kobj_array[p_tmp_hash].p_mod_core_text_hash != p_module_kobj_tmp[p_tmp_cnt].p_mod_core_text_hash) {
                  p_print_log(P_LKRG_CRIT,
                         "[KOBJ] ALERT !!! MODULE'S <%s> HASH IS DIFFERENT it is [0x%llx] and should be [0x%llx] !!!\n",
                          p_module_kobj_tmp[p_tmp_hash].p_name,
                          p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash,
                          p_db.p_module_kobj_array[p_tmp_cnt].p_mod_core_text_hash);
                  P_KINT_IF_ACCEPT(p_db.p_module_kobj_array[p_tmp_cnt].p_mod_core_text_hash,
                                   p_module_kobj_tmp[p_tmp_hash].p_mod_core_text_hash,
                                   p_hack_check);
               }
         }
      }
   }

   if (p_hack_check) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! SYSTEM HAS BEEN COMPROMISED - DETECTED DIFFERENT %u CHECKSUMS !!!\n",p_hack_check);
      if (P_CTRL(p_kint_enforce == 2)) {
         // OK, we need to crash the kernel now
         panic(P_LKRG_SIGNATURE "Kernel Integrity verification failed! Killing the kernel...\n");
      }
   } else if (P_CTRL(p_heartbeat)) {
      p_print_log(P_LKRG_ALIVE,"System is clean!\n");
   }

   if (p_module_list_tmp) {
      kzfree(p_module_list_tmp);
      p_module_list_tmp = NULL;
   }
   if (p_module_kobj_tmp) {
      kzfree(p_module_kobj_tmp);
      p_module_kobj_tmp = NULL;
   }

   /* God mode off ;) */
   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
//   spin_unlock(&p_db_lock);

p_check_integrity_cancel:

   p_text_section_unlock();
   if (p_tmp_cpus) {
      kzfree(p_tmp_cpus);
      p_tmp_cpus = NULL;
   }

p_check_integrity_tasks:

   if (!p_ed_enforce_validation_paranoid()) {
      if (P_CTRL(p_heartbeat) && P_CTRL(p_pint_validate) &&
          (!P_CTRL(p_kint_validate) || (!p_manual && P_CTRL(p_kint_validate) == 1))) {
         p_print_log(P_LKRG_ALIVE,"Tasks are clean!\n");
      }
   }

   if (p_manual)
      p_manual = 0;

   /* Free the worker struct */
   if (p_work) {
      p_free_offload(p_work);
   }
}
