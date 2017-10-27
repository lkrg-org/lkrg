/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *   => submodule for checking system configuration regarding CPUs
 *
 * Notes:
 *  - Some of the critical data may exists per logical CPU (core)
 *    and need to be independently verified / checked.
 *    Additionally, it is strongly dependend from the architecture.
 *    Linux kernel defines different types of CPUs:
 *     => online CPUs
 *     => possible CPUs
 *     => present CPUs
 *     => active CPUs
 *
 *    This module will keep information about how many 'active CPUs',
 *    'online CPUs' and 'present CPUs' exists in the current system.
 *    Additionally Linux kernel exports global CPU id count ('nr_cpu_ids')
 *    which is initialized per boot time. If over the time any of the
 *    CPU will be hot plugged / activated this information will be
 *    visible for us!
 *
 *  - x86 (and amd64) arch: following informations are critical and need
 *    to be verified (checking integrity):
 *     => IDT base and/or entire table
 *     => MSRs
 *
 *  - Since Linux 4.10 there isn't CPU_[ONLINE/DEAD] notifiers :(
 *    Hot CPU plug[in/out] notification logic has completaly changed. More information
 *    Can be found here:
 *     => https://patchwork.kernel.org/patch/9448577/
 *    On new kernel (4.10.+) we use modern hot CPU plug[in/out] logic.
 *
 * Timeline:
 *  - Created: 28.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

/*
 * #define get_cpu()               ({ preempt_disable(); smp_processor_id(); })
 * #define put_cpu()               preempt_enable()
 */

void p_get_cpus(p_cpu_info *p_arg) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_get_cpus>\n");

   memset(p_arg,0x0,sizeof(p_cpu_info));

   p_arg->online_CPUs = num_online_cpus();
   p_arg->possible_CPUs = num_possible_cpus();
   p_arg->present_CPUs = num_present_cpus();
   p_arg->active_CPUs = num_active_cpus();

   p_arg->p_nr_cpu_ids = nr_cpu_ids;

   p_debug_log(P_LKRG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "<p_get_cpus> online[%d] possible[%d] present[%d] active[%d] nr_cpu_ids[%d]\n",
          p_arg->online_CPUs,p_arg->possible_CPUs,p_arg->present_CPUs,p_arg->active_CPUs,
          p_arg->p_nr_cpu_ids);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_get_cpus>\n");

}

int p_cmp_cpus(p_cpu_info *p_arg1, p_cpu_info *p_arg2) {

   int p_flag = 0x0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_cmp_cpus>\n");

   if (p_arg1->online_CPUs != p_arg2->online_CPUs) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! NUMBER OF ONLINE CPUs IS DIFFERENT !!!\n");
      p_flag++;
   }
   if (p_arg1->possible_CPUs != p_arg2->possible_CPUs) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! NUMBER OF POSSIBLE CPUs IS DIFFERENT !!!\n");
      p_flag++;
   }
   if (p_arg1->present_CPUs != p_arg2->present_CPUs) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! NUMBER OF PRESENT CPUs IS DIFFERENT !!!\n");
      p_flag++;
   }
   if (p_arg1->active_CPUs != p_arg2->active_CPUs) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! NUMBER OF ACTIVE CPUs IS DIFFERENT !!!\n");
      p_flag++;
   }
   if (p_arg1->p_nr_cpu_ids != p_arg2->p_nr_cpu_ids) {
      p_print_log(P_LKRG_CRIT,
             "ALERT !!! VARIABLE 'nr_cpu_ids' IS DIFFERENT !!!\n");
      p_flag++;
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_cmp_cpus>\n");

   return p_flag;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
/*
 * Notification routine when new CPU is online or become offline.
 * It may be critical from the security point of view, because new per-CPU
 * metadata must be set-up. We must write them down and verify it.
 */
int p_cpu_callback(struct notifier_block *p_block, unsigned long p_action, void *p_hcpu) {

   unsigned int p_cpu = (unsigned long)p_hcpu;


// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_cpu_callback>\n");

// TODO: lock db
//       lock is done in the individual action function
//       to reduce locking/starving time

   switch (p_action) {

      case CPU_ONLINE:
      case CPU_ONLINE_FROZEN:
          p_cpu_online_action(p_cpu);
          break;

      case CPU_DEAD:
      case CPU_DEAD_FROZEN:
          p_cpu_dead_action(p_cpu);
          break;
   }

// TODO: unlock db
//       lock is done in the individual action function
//       to reduce locking/starving time

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_cpu_callback>\n");

   return NOTIFY_OK;
}
#endif


int p_cpu_online_action(unsigned int p_cpu) {

   int tmp_online_CPUs = p_db.p_cpu.online_CPUs;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Entering function <p_cpu_online_action>\n");

   /* We are heavly consuming module list here - take 'module_mutex' */
   mutex_lock(&module_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   /* Hacky way of 'stopping' KOBJs activities */
   mutex_lock(p_kernfs_mutex);
#endif

   spin_lock(&p_db_lock);

   smp_call_function_single(p_cpu,p_dump_IDT_MSR_CRx,p_db.p_IDT_MSR_CRx_array,true);

   /* Let's play... God mode on ;) */
//   spin_lock_irqsave(&p_db_lock,p_db_flags);

   p_get_cpus(&p_db.p_cpu);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
   p_db.p_cpu.active_CPUs++;
#endif
   p_db.p_IDT_MSR_CRx_hashes = hash_from_CPU_data(p_db.p_IDT_MSR_CRx_array);

   /* UP kernel became SMP one! we need to do more work ;/ */
   if (tmp_online_CPUs == 1 && p_db.p_cpu.online_CPUs > 1) {
      /* First recalculate _STEXT and other critical kernel's data - now is SMPbooted! */
      if (hash_from_ex_table() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU ONLINE ERROR: CANNOT GET HASH FROM EXCEPTION TABLE!\n");
      }
      if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU ONLINE ERROR: CANNOT GET HASH FROM _STEXT!\n");
      }
      if (hash_from_kernel_rodata() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU ONLINE ERROR: CANNOT GET HASH FROM _RODATA!\n");
      }
      if (hash_from_iommu_table() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU ONLINE ERROR: CANNOT GET HASH FROM IOMMU TABLE!\n");
      }
      /* Now recalculate modules, again some macros are different now ! */
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

      p_print_log(P_LKRG_INFO,"Hash from 'module list' => [0x%x]\n",p_db.p_module_list_hash);
      p_print_log(P_LKRG_INFO,"Hash from 'module kobj(s)' => [0x%x]\n",p_db.p_module_kobj_hash);

      /* We should be fine now! */
   }

   /* God mode off ;) */
//   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
   spin_unlock(&p_db_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   /* unlock KOBJ activities */
   mutex_unlock(p_kernfs_mutex);
#endif
   /* Release the 'module_mutex' */
   mutex_unlock(&module_mutex);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_cpu_online_action>\n");

   return 0x0;
}

int p_cpu_dead_action(unsigned int p_cpu) {

   int tmp_online_CPUs = p_db.p_cpu.online_CPUs;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Entering function <p_cpu_dead_action>\n");

   /* We are heavly consuming module list here - take 'module_mutex' */
   mutex_lock(&module_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   /* Hacky way of 'stopping' KOBJs activities */
   mutex_lock(p_kernfs_mutex);
#endif

   spin_lock(&p_db_lock);

   p_db.p_IDT_MSR_CRx_array[p_cpu].p_cpu_online = P_CPU_OFFLINE;

   /* Update database */

   /* Let's play... God mode on ;) */
//   spin_lock_irqsave(&p_db_lock,p_db_flags);

   p_get_cpus(&p_db.p_cpu);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
   p_db.p_cpu.online_CPUs--;
#endif
   p_db.p_IDT_MSR_CRx_hashes = hash_from_CPU_data(p_db.p_IDT_MSR_CRx_array);

   /*
    * SMP kernel might became UP one! Never had a chance to test it ;/
    * In case when UP kernel starting to be SMP one, some critical macros
    * are changed and hashes from TEXT section of kernel core AND modules
    * are changing so we recalculating them. It is possible we should follow
    * the same scenario in this situation...
    */
   if (tmp_online_CPUs > 1 && p_db.p_cpu.online_CPUs == 1) {
      /* First recalculate _STEXT and other critical kernel's data - now is not SMPbooted! */
      if (hash_from_ex_table() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU OFFLINE ERROR: CANNOT GET HASH FROM EXCEPTION TABLE!\n");
      }
      if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU OFFLINE ERROR: CANNOT GET HASH FROM _STEXT!\n");
      }
      if (hash_from_kernel_rodata() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU OFFLINE ERROR: CANNOT GET HASH FROM _RODATA!\n");
      }
      if (hash_from_iommu_table() != P_LKRG_SUCCESS) {
         p_print_log(P_LKRG_CRIT,
            "CPU OFFLINE ERROR: CANNOT GET HASH FROM IOMMU TABLE!\n");
      }
      /* Now recalculate modules, again some macros are different now ! */
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

      p_print_log(P_LKRG_INFO,"Hash from 'module list' => [0x%x]\n",p_db.p_module_list_hash);
      p_print_log(P_LKRG_INFO,"Hash from 'module kobj(s)' => [0x%x]\n",p_db.p_module_kobj_hash);

      /* We should be fine now! */
   }

   /* God mode off ;) */
//   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
   spin_unlock(&p_db_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
   /* unlock KOBJ activities */
   mutex_unlock(p_kernfs_mutex);
#endif
   /* Release the 'module_mutex' */
   mutex_unlock(&module_mutex);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
//   p_print_log(P_LKRG_CRIT,
          "Leaving function <p_cpu_dead_action>\n");

   return 0x0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
struct notifier_block p_cpu_notifier =
{
   .notifier_call = p_cpu_callback,
};
#endif
