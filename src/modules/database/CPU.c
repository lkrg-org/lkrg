/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *   => submodule for checking system configuration regarding CPUs
 *
 * Notes:
 *  - Some of the critical data may exist per logical CPU (core)
 *    and need to be independently verified / checked.
 *    Additionally, it is strongly dependent on the architecture.
 *    Linux kernel defines different types of CPUs:
 *     => online CPUs
 *     => possible CPUs
 *     => present CPUs
 *     => active CPUs
 *
 *    This module will keep information about how many 'active CPUs',
 *    'online CPUs' and 'present CPUs' exist in the current system.
 *    Additionally, Linux kernel exports global CPU id count ('nr_cpu_ids'),
 *    which is initialized per boot time. If over the time any of the
 *    CPU will be hot plugged / activated this information will be
 *    visible for us!
 *
 *  - x86 (and amd64) arch: the following pieces of information are
 *    critical and need to be verified (checking integrity):
 *     => IDT base and/or entire table
 *     => MSRs
 *
 *  - Since Linux 4.10 there isn't CPU_[ONLINE/DEAD] notifiers :(
 *    Hot CPU plug[in/out] notification logic has completely changed.
 *    More information can be found here:
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

   memset(p_arg,0,sizeof(p_cpu_info));

   p_arg->online_CPUs = num_online_cpus();
   p_arg->possible_CPUs = num_possible_cpus();
   p_arg->present_CPUs = num_present_cpus();
   p_arg->active_CPUs = num_active_cpus();

   p_arg->p_nr_cpu_ids = nr_cpu_ids;

   p_debug_log(P_LOG_DEBUG,
          "<p_get_cpus> online[%d] possible[%d] present[%d] active[%d] nr_cpu_ids[%d]",
          p_arg->online_CPUs,p_arg->possible_CPUs,p_arg->present_CPUs,p_arg->active_CPUs,
          p_arg->p_nr_cpu_ids);
}

int p_cmp_cpus(p_cpu_info *p_orig, p_cpu_info *p_current) {

   int p_flag = 0;

#define P_CMP_CPU(which) \
   if (p_orig->which ## _CPUs != p_current->which ## _CPUs) { \
      p_print_log(P_LOG_FAULT, "Number of " #which " CPUs changed unexpectedly (expected %u, actual %u)", \
         p_orig->which ## _CPUs, p_current->which ## _CPUs); \
      p_flag++; \
   }

   P_CMP_CPU(online)
   P_CMP_CPU(possible)
   P_CMP_CPU(present)
   P_CMP_CPU(active)

   if (p_orig->p_nr_cpu_ids != p_current->p_nr_cpu_ids) {
      p_print_log(P_LOG_FAULT, "'nr_cpu_ids' changed unexpectedly (expected %u, actual %u)",
         p_orig->p_nr_cpu_ids, p_current->p_nr_cpu_ids);
      p_flag++;
   }

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

   return NOTIFY_OK;
}
#endif

static void p_cpu_rehash(const char *onoffline) {
   /* First recalculate _STEXT and other critical kernel's data */
   if (hash_from_ex_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "CPU %s: Can't get hash from exception table", onoffline);
   }
   if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "CPU %s: Can't get hash from _stext", onoffline);
   }
   if (hash_from_kernel_rodata() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "CPU %s: Can't get hash from _rodata", onoffline);
   }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
   if (hash_from_iommu_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "CPU %s: Can't get hash from IOMMU table", onoffline);
   }
#endif

   /* Now recalculate modules, again some macros are different now ! */

   /* OK, now recalculate hashes again! */
   while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                     &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array, 0x2) != P_LKRG_SUCCESS)
      schedule();

   /* Update global module list/kobj hash */
   p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                          (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));

   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));

   p_print_log(P_LOG_WATCH, "Hash from 'module list' => [0x%llx]", p_db.p_module_list_hash);
   p_print_log(P_LOG_WATCH, "Hash from 'module kobj(s)' => [0x%llx]", p_db.p_module_kobj_hash);

   /* We should be fine now! */
}

int p_cpu_online_action(unsigned int p_cpu) {

   int tmp_online_CPUs = p_db.p_cpu.online_CPUs;

   p_text_section_lock();
   spin_lock(&p_db_lock);

   smp_call_function_single(p_cpu,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);

   /* Let's play... God mode on ;) */
//   spin_lock_irqsave(&p_db_lock,p_db_flags);

   p_get_cpus(&p_db.p_cpu);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
   p_db.p_cpu.active_CPUs++;
#endif
   p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);

   /* UP kernel became SMP one! we need to do more work ;/ */
   if (tmp_online_CPUs == 1 && p_db.p_cpu.online_CPUs > 1) {
      /* now is SMPbooted! */
      p_cpu_rehash("online");
   }

   /* God mode off ;) */
//   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
   spin_unlock(&p_db_lock);
   p_text_section_unlock();

   return 0;
}

int p_cpu_dead_action(unsigned int p_cpu) {

   int tmp_online_CPUs = p_db.p_cpu.online_CPUs;

   p_text_section_lock();
   spin_lock(&p_db_lock);

   p_db.p_CPU_metadata_array[p_cpu].p_cpu_online = P_CPU_OFFLINE;

   /* Update database */

   /* Let's play... God mode on ;) */
//   spin_lock_irqsave(&p_db_lock,p_db_flags);

   p_get_cpus(&p_db.p_cpu);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
   p_db.p_cpu.online_CPUs--;
#endif
   p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);

   /*
    * SMP kernel might became UP one! Never had a chance to test it ;/
    * In case when UP kernel starting to be SMP one, some critical macros
    * are changed and hashes from TEXT section of kernel core AND modules
    * are changing so we recalculating them. It is possible we should follow
    * the same scenario in this situation...
    */
   if (tmp_online_CPUs > 1 && p_db.p_cpu.online_CPUs == 1) {
      /* now is not SMPbooted! */
      p_cpu_rehash("offline");
   }

   /* God mode off ;) */
//   spin_unlock_irqrestore(&p_db_lock,p_db_flags);
   spin_unlock(&p_db_lock);
   p_text_section_unlock();

   return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
struct notifier_block p_cpu_notifier =
{
   .notifier_call = p_cpu_callback,
};
#endif
