/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *
 * Notes:
 *  - Let's create database - calculate hashes
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

p_hash_database p_db;

int hash_from_ex_table(void) {

   unsigned long p_tmp = 0;

   p_db.kernel_ex_table.p_addr = (unsigned long *)P_SYM(p_kallsyms_lookup_name)("__start___ex_table");
   p_tmp = (unsigned long)P_SYM(p_kallsyms_lookup_name)("__stop___ex_table");

   if (!p_db.kernel_ex_table.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_ex_table.p_addr) {
      return P_LKRG_GENERAL_ERROR;
   }

   p_db.kernel_ex_table.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_ex_table.p_addr);

   p_db.kernel_ex_table.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_ex_table.p_addr,
                                                  (unsigned int)p_db.kernel_ex_table.p_size);

   p_debug_log(P_LOG_DEBUG,
          "hash [0x%llx] ___ex_table start [0x%lx] size [0x%lx]",p_db.kernel_ex_table.p_hash,
                                                                   (long)p_db.kernel_ex_table.p_addr,
                                                                   (long)p_db.kernel_ex_table.p_size);

   return P_LKRG_SUCCESS;
}

int hash_from_kernel_stext(void) {

   unsigned long p_tmp = 0;

   p_db.kernel_stext.p_addr = (unsigned long *)P_SYM(p_kallsyms_lookup_name)("_stext");
   p_tmp = (unsigned long)P_SYM(p_kallsyms_lookup_name)("_etext");

   if (!p_db.kernel_stext.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_stext.p_addr) {
      return P_LKRG_GENERAL_ERROR;
   }

   p_db.kernel_stext.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_stext.p_addr);
   p_db.kernel_stext.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_stext.p_addr,
                                               (unsigned int)p_db.kernel_stext.p_size);


#if defined(P_LKRG_JUMP_LABEL_STEXT_DEBUG)
   if (!p_db.kernel_stext_copy) {
      if ( (p_db.kernel_stext_copy = vmalloc(p_db.kernel_stext.p_size+1)) == NULL) {
         /*
          * I should NEVER be here!
          */
         p_print_log(P_LOG_FATAL, "Can't allocate memory for _stext copy");
         return P_LKRG_GENERAL_ERROR;
      }
   }
   memcpy(p_db.kernel_stext_copy,p_db.kernel_stext.p_addr,p_db.kernel_stext.p_size);
   p_db.kernel_stext_copy[p_db.kernel_stext.p_size] = 0;
#endif

   p_debug_log(P_LOG_DEBUG,
          "hash [0x%llx] _stext start [0x%lx] size [0x%lx]",p_db.kernel_stext.p_hash,
                                                              (long)p_db.kernel_stext.p_addr,
                                                              (long)p_db.kernel_stext.p_size);
   return P_LKRG_SUCCESS;
}

int hash_from_kernel_rodata(void) {

   unsigned long p_tmp = 0;

   p_db.kernel_rodata.p_addr = (unsigned long *)P_SYM(p_kallsyms_lookup_name)("__start_rodata");
   p_tmp = (unsigned long)P_SYM(p_kallsyms_lookup_name)("__end_rodata");

   if (!p_db.kernel_rodata.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_rodata.p_addr) {
      return P_LKRG_GENERAL_ERROR;
   }

   p_db.kernel_rodata.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_rodata.p_addr);

#if !defined(CONFIG_GRKERNSEC)

   p_db.kernel_rodata.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_rodata.p_addr,
                                                (unsigned int)p_db.kernel_rodata.p_size);

#else

   p_db.kernel_rodata.p_hash = 0xFFFFFFFF;

#endif

   p_debug_log(P_LOG_DEBUG,
          "hash [0x%llx] _rodata start [0x%lx] size [0x%lx]",p_db.kernel_rodata.p_hash,
                                                               (long)p_db.kernel_rodata.p_addr,
                                                               (long)p_db.kernel_rodata.p_size);
   return P_LKRG_SUCCESS;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
int hash_from_iommu_table(void) {

#ifdef CONFIG_X86
   unsigned long p_tmp = 0;

   p_db.kernel_iommu_table.p_addr = (unsigned long *)P_SYM(p_kallsyms_lookup_name)("__iommu_table");
   p_tmp = (unsigned long)P_SYM(p_kallsyms_lookup_name)("__iommu_table_end");

   if (!p_db.kernel_iommu_table.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_iommu_table.p_addr) {
      return P_LKRG_GENERAL_ERROR;
   }

   p_db.kernel_iommu_table.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_iommu_table.p_addr);


#ifdef P_LKRG_IOMMU_HASH_ENABLED
   p_db.kernel_iommu_table.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_iommu_table.p_addr,
                                                     (unsigned int)p_db.kernel_iommu_table.p_size);
#else
// Static value - might change in normal system...
   p_db.kernel_iommu_table.p_hash = 0xFFFFFFFF;
#endif

   p_debug_log(P_LOG_DEBUG,
          "hash [0x%llx] __iommu_table start [0x%lx] size [0x%lx]",p_db.kernel_iommu_table.p_hash,
                                                                     (long)p_db.kernel_iommu_table.p_addr,
                                                                     (long)p_db.kernel_iommu_table.p_size);

#else

// Static value - might change in normal system...
   p_db.kernel_iommu_table.p_hash = 0xFFFFFFFF;

#endif

   return P_LKRG_SUCCESS;
}
#endif

uint64_t hash_from_CPU_data(p_CPU_metadata_hash_mem *p_arg) {

   unsigned int p_tmp = 0;
   uint64_t p_hash = 0;

   for_each_present_cpu(p_tmp) {
      if (p_arg[p_tmp].p_cpu_online == P_CPU_ONLINE) {
         if (cpu_online(p_tmp)) {
            if (P_CTRL(p_msr_validate)) {
               p_hash ^= p_lkrg_fast_hash((unsigned char *)&p_arg[p_tmp],
                                          (unsigned int)sizeof(p_CPU_metadata_hash_mem));
            } else {
               p_hash ^= p_lkrg_fast_hash((unsigned char *)&p_arg[p_tmp],
                                          (unsigned int)offsetof(p_CPU_metadata_hash_mem, p_MSR_marker));
            }
            p_debug_log(P_LOG_DEBUG,
                   "<hash_from_CPU_data> Hash for CPU %u total_hash[0x%llx]", p_tmp, p_hash);
         } else {
          // WTF?! I should never be here
            p_print_log(P_LOG_FAULT, "CPU %u is unexpectedly offline", p_tmp);
         }
      } else {
      // Skip offline CPUs
         p_debug_log(P_LOG_DEBUG,
                "<hash_from_CPU_data> Offline CPU %u total_hash[0x%llx]", p_tmp, p_hash);
      }
   }

   return p_hash;
}

int p_create_database(void) {

   int p_tmp;
//   int p_tmp_cpu;

   memset(&p_db,0,sizeof(p_hash_database));

   P_SYM_INIT(jump_label_mutex, struct mutex *)
   P_SYM_INIT(text_mutex, struct mutex *)

   /*
    * First gather information about CPUs in the system - CRITICAL !!!
    */
   p_get_cpus(&p_db.p_cpu);

   /*
    * OK, we now know what is the maximum number of supported CPUs
    * in this kernel, let's allocate data here...
    */
   /*
    * This is one-shot function not in the time-critical context/section. We can sleep here so
    * we are allowed to make 'slowpath' memory allocation - don't need to use emergency pools.
    *
    * __GFP_NOFAIL flag will always generate slowpath warn because developers
    * decided to depreciate this flag ;/
    */
   if ( (p_db.p_CPU_metadata_array = kzalloc(sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids,
                                                                  GFP_KERNEL | __GFP_REPEAT)) == NULL) {
      /*
       * I should NEVER be here!
       */
      p_print_log(P_LOG_FATAL, "Can't allocate memory for CPU metadata");
      return P_LKRG_GENERAL_ERROR;
   }
// STRONG_DEBUG
     else {
        p_debug_log(P_LOG_FLOOD,
               "<p_create_database> p_db.p_CPU_metadata_array[0x%lx] with requested size[%d] "
               "= sizeof(p_CPU_metadata_hash_mem)[%d] * p_db.p_cpu.p_nr_cpu_ids[%d]",
               (unsigned long)p_db.p_CPU_metadata_array,
               (int)(sizeof(p_CPU_metadata_hash_mem)*p_db.p_cpu.p_nr_cpu_ids),
               (int)sizeof(p_CPU_metadata_hash_mem),p_db.p_cpu.p_nr_cpu_ids);
   }

   /*
    * OK, we have prepared all necessary memory. Let's try X86 specific
    * function
    */

//   p_tmp_cpu = get_cpu();

   /*
    * Sometime this function has problems and do not run on every requested CPU:
    *   smp_call_function_many(cpu_present_mask, ...);
    *
    * that's why we do it manually now:
    */
   for_each_present_cpu(p_tmp) {
      if (cpu_online(p_tmp)) {
//         if (p_tmp_cpu != p_tmp) {
//          p_dump_CPU_metadata(p_db.p_CPU_metadata_array);

            /*
             * There is an undesirable situation in SMP Linux machines when sending
             * IPI via the smp_call_function_single() API...
             *
             * ... more technical details about it can be found here:
             *  *) http://blog.pi3.com.pl/?p=549
             *  *) http://lists.openwall.net/linux-kernel/2016/09/21/68
             */
            smp_call_function_single(p_tmp,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
//         }
      } else {
         p_print_log(P_LOG_ISSUE,
                "!!! WARNING !!! CPU ID:%d is offline !!!",p_tmp);
//                "Let's try to run on it anyway...",p_tmp);
//         p_dump_CPU_metadata(p_db.p_CPU_metadata_array);
//         smp_call_function_single(p_tmp,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);
      }
   }
//   put_cpu();
//   smp_call_function_single(p_tmp_cpu,p_dump_CPU_metadata,p_db.p_CPU_metadata_array,true);

   p_db.p_CPU_metadata_hashes = hash_from_CPU_data(p_db.p_CPU_metadata_array);

   /* Some arch needs extra hooks */
   if (p_register_arch_metadata() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FATAL, "Can't register CPU architecture specific metadata");
      return P_LKRG_GENERAL_ERROR;
   }


   if (hash_from_ex_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "Exception table can't be found (skipping)");
      p_db.kernel_ex_table.p_hash = p_db.kernel_ex_table.p_size = 0;
      p_db.kernel_ex_table.p_addr = NULL;
   }


   if (hash_from_kernel_rodata() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FAULT, "_rodata can't be found (skipping)");
      p_db.kernel_rodata.p_hash = p_db.kernel_rodata.p_size = 0;
      p_db.kernel_rodata.p_addr = NULL;
   }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
   if (hash_from_iommu_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_ISSUE, "IOMMU table can't be found (skipping)");
      p_db.kernel_iommu_table.p_hash = p_db.kernel_iommu_table.p_size = 0;
      p_db.kernel_iommu_table.p_addr = NULL;
   }
#endif

#if defined(CONFIG_OPTPROBES)
   P_SYM(p_wait_for_kprobe_optimizer)();
#endif
   smp_mb();

   p_text_section_lock();

   /*
    * Memory allocation may fail... let's loop here!
    */
   while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                     &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array, 0x1) != P_LKRG_SUCCESS)
      schedule();

   /* Hash */
   p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                          (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));
   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
/*

   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));
*/

   p_text_section_unlock();

   /* Register module notification routine - must be outside p_text_section_(un)lock */
   p_register_module_notifier();

   p_debug_log(P_LOG_DEBUG,
          "p_module_list_hash => [0x%llx] p_module_kobj_hash => [0x%llx]",
          p_db.p_module_list_hash,p_db.p_module_kobj_hash);

   P_SYM(p_state_init) = 1;
#if defined(CONFIG_OPTPROBES)
   P_SYM(p_wait_for_kprobe_optimizer)();
#endif
   smp_mb();

#if !defined(CONFIG_GRKERNSEC)
   p_text_section_lock();
   if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
      p_print_log(P_LOG_FATAL, "Can't compute hash from _stext");
      p_text_section_unlock();
      return P_LKRG_GENERAL_ERROR;
   }
   p_text_section_unlock();
#endif

   return P_LKRG_SUCCESS;

p_sym_error:
   return P_LKRG_GENERAL_ERROR;
}
