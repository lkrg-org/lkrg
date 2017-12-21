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

   unsigned long p_tmp = 0x0;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <hash_from_ex_table>\n");

   p_db.kernel_ex_table.p_addr = (unsigned long *)p_kallsyms_lookup_name("__start___ex_table");
   p_tmp = (unsigned long)p_kallsyms_lookup_name("__stop___ex_table");

   if (!p_db.kernel_ex_table.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_ex_table.p_addr) {
      p_ret = P_LKRG_GENERAL_ERROR;
      goto hash_from_ex_table_out;
   }

   p_db.kernel_ex_table.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_ex_table.p_addr);

   p_db.kernel_ex_table.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_ex_table.p_addr,
                                                  (unsigned int)p_db.kernel_ex_table.p_size);

   p_debug_log(P_LKRG_DBG,
          "hash [0x%llx] ___ex_table start [0x%lx] size [0x%lx]\n",p_db.kernel_ex_table.p_hash,
                                                                   (long)p_db.kernel_ex_table.p_addr,
                                                                   (long)p_db.kernel_ex_table.p_size);

hash_from_ex_table_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <hash_from_ex_table> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int hash_from_kernel_stext(void) {

   unsigned long p_tmp = 0x0;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <hash_from_kernel_stext>\n");

   p_db.kernel_stext.p_addr = (unsigned long *)p_kallsyms_lookup_name("_stext");
   p_tmp = (unsigned long)p_kallsyms_lookup_name("_etext");

   if (!p_db.kernel_stext.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_stext.p_addr) {
      p_ret = P_LKRG_GENERAL_ERROR;
      goto hash_from_kernel_stext_out;
   }

   p_db.kernel_stext.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_stext.p_addr);

   p_db.kernel_stext.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_stext.p_addr,
                                               (unsigned int)p_db.kernel_stext.p_size);

/* It is NOT only for debugging... *_JMP_LABEL sux! */
   if ( (p_db.kernel_stext_copy.p_addr = vmalloc(p_db.kernel_stext.p_size+1)) == NULL) {
      /*
       * I should NEVER be here!
       */
      p_print_log(P_LKRG_CRIT,
             "hash_from_kernel_stext(): kzalloc() error! Can't allocate memory [size %ld:0x%lx] ;[\n",
             p_db.kernel_stext.p_size+1,p_db.kernel_stext.p_size+1);
      p_ret = P_LKRG_GENERAL_ERROR;
      goto hash_from_kernel_stext_out;
   }

//   memset(p_db.kernel_stext_copy.p_addr,0x0,p_db.kernel_stext.p_size+1);
   *((char *)p_db.kernel_stext_copy.p_addr + p_db.kernel_stext.p_size) = 0x0;
   memcpy(p_db.kernel_stext_copy.p_addr,p_db.kernel_stext.p_addr,p_db.kernel_stext.p_size);
   p_db.kernel_stext_copy.p_size = p_db.kernel_stext.p_size;

   p_db.kernel_stext_copy.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_stext_copy.p_addr,
                                                    (unsigned int)p_db.kernel_stext_copy.p_size);

   p_debug_log(P_LKRG_DBG,
          "hash [0x%llx] _stext start [0x%lx] size [0x%lx]\n",p_db.kernel_stext.p_hash,
                                                              (long)p_db.kernel_stext.p_addr,
                                                              (long)p_db.kernel_stext.p_size);

hash_from_kernel_stext_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <hash_from_kernel_stext> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int hash_from_kernel_rodata(void) {

   unsigned long p_tmp = 0x0;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <hash_from_kernel_rodata>\n");

   p_db.kernel_rodata.p_addr = (unsigned long *)p_kallsyms_lookup_name("__start_rodata");
   p_tmp = (unsigned long)p_kallsyms_lookup_name("__end_rodata");

   if (!p_db.kernel_rodata.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_rodata.p_addr) {
      p_ret = P_LKRG_GENERAL_ERROR;
      goto hash_from_kernel_rodata_out;
   }

   p_db.kernel_rodata.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_rodata.p_addr);

   p_db.kernel_rodata.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_rodata.p_addr,
                                                (unsigned int)p_db.kernel_rodata.p_size);

   p_debug_log(P_LKRG_DBG,
          "hash [0x%llx] _rodata start [0x%lx] size [0x%lx]\n",p_db.kernel_rodata.p_hash,
                                                               (long)p_db.kernel_rodata.p_addr,
                                                               (long)p_db.kernel_rodata.p_size);

hash_from_kernel_rodata_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <hash_from_kernel_rodata> (p_ret => %d)\n",p_ret);

   return p_ret;
}

int hash_from_iommu_table(void) {

   unsigned long p_tmp = 0x0;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <hash_from_iommu_table>\n");

   p_db.kernel_iommu_table.p_addr = (unsigned long *)p_kallsyms_lookup_name("__iommu_table");
   p_tmp = (unsigned long)p_kallsyms_lookup_name("__iommu_table_end");

   if (!p_db.kernel_iommu_table.p_addr || !p_tmp || p_tmp < (unsigned long)p_db.kernel_iommu_table.p_addr) {
      p_ret = P_LKRG_GENERAL_ERROR;
      goto hash_from_iommu_table_out;
   }

   p_db.kernel_iommu_table.p_size = (unsigned long)(p_tmp - (unsigned long)p_db.kernel_iommu_table.p_addr);


#ifdef P_LKRG_IOMMU_HASH_ENABLED
   p_db.kernel_iommu_table.p_hash = p_lkrg_fast_hash((unsigned char *)p_db.kernel_iommu_table.p_addr,
                                                     (unsigned int)p_db.kernel_iommu_table.p_size);
#else
// Static value - might change in normal system...
   p_db.kernel_iommu_table.p_hash = 0xFFFFFFFF;
#endif

   p_debug_log(P_LKRG_DBG,
          "hash [0x%llx] __iommu_table start [0x%lx] size [0x%lx]\n",p_db.kernel_iommu_table.p_hash,
                                                                     (long)p_db.kernel_iommu_table.p_addr,
                                                                     (long)p_db.kernel_iommu_table.p_size);

hash_from_iommu_table_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <hash_from_iommu_table> (p_ret => %d)\n",p_ret);

   return p_ret;
}

uint64_t hash_from_CPU_data(p_IDT_MSR_CRx_hash_mem *p_arg) {

   int p_tmp = 0x0;
   uint64_t p_hash = 0x0;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <hash_from_CPU_data>\n");

   for_each_present_cpu(p_tmp) {
      if (p_arg[p_tmp].p_cpu_online == P_CPU_ONLINE) {
         if (cpu_online(p_tmp)) {
            p_hash ^= p_lkrg_fast_hash((unsigned char *)&p_arg[p_tmp],
                                       (unsigned int)sizeof(p_IDT_MSR_CRx_hash_mem));
            p_debug_log(P_LKRG_DBG,
                   "<hash_from_CPU_data> Hash for cpu id %i total_hash[0x%llx]\n",p_tmp,p_hash);
         } else {
          // WTF?! I should never be here
            p_print_log(P_LKRG_CRIT,
                   "WTF?! DB corrupted?");
         }
      } else {
      // Skip offline CPUs
         p_debug_log(P_LKRG_DBG,
                "<hash_from_CPU_data> Offline cpu id %i total_hash[0x%llx]\n",p_tmp,p_hash);
      }
   }

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <hash_from_CPU_data>\n");

   return p_hash;
}


int p_create_database(void) {

   int p_tmp;
//   int p_tmp_cpu;
   int p_ret = P_LKRG_SUCCESS;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_create_database>\n");

   memset(&p_db,0x0,sizeof(p_hash_database));

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
   if ( (p_db.p_IDT_MSR_CRx_array = kzalloc(sizeof(p_IDT_MSR_CRx_hash_mem)*p_db.p_cpu.p_nr_cpu_ids,
                                                                  GFP_KERNEL | __GFP_REPEAT)) == NULL) {
      /*
       * I should NEVER be here!
       */
      p_print_log(P_LKRG_CRIT,
             "CREATING DATABASE: kzalloc() error! Can't allocate memory ;[\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_create_database_out;
   }
// STRONG_DEBUG
     else {
        p_debug_log(P_LKRG_STRONG_DBG,
               "<p_create_database> p_db.p_IDT_MSR_CRx_array[%p] with requested size[%d] "
               "= sizeof(p_IDT_MSR_CRx_hash_mem)[%d] * p_db.p_cpu.p_nr_cpu_ids[%d]\n",
               p_db.p_IDT_MSR_CRx_array,(int)(sizeof(p_IDT_MSR_CRx_hash_mem)*p_db.p_cpu.p_nr_cpu_ids),
               (int)sizeof(p_IDT_MSR_CRx_hash_mem),p_db.p_cpu.p_nr_cpu_ids);
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
//          p_dump_IDT_MSR_CRx(p_db.p_IDT_MSR_CRx_array);

            /*
             * There is an undesirable situation in SMP Linux machines when sending
             * IPI via the smp_call_function_single() API...
             *
             * ... more technical details about it can be found here:
             *  *) http://blog.pi3.com.pl/?p=549
             *  *) http://lkml.iu.edu/hypermail/linux/kernel/1609.2/03265.html
             */
            smp_call_function_single(p_tmp,p_dump_IDT_MSR_CRx,p_db.p_IDT_MSR_CRx_array,true);
//         }
      } else {
         p_print_log(P_LKRG_WARN,
                "!!! WARNING !!! CPU ID:%d is offline !!!\n",p_tmp);
//                "Let's try to run on it anyway...",p_tmp);
//         p_dump_IDT_MSR_CRx(p_db.p_IDT_MSR_CRx_array);
//         smp_call_function_single(p_tmp,p_dump_IDT_MSR_CRx,p_db.p_IDT_MSR_CRx_array,true);
      }
   }
//   put_cpu();
//   smp_call_function_single(p_tmp_cpu,p_dump_IDT_MSR_CRx,p_db.p_IDT_MSR_CRx_array,true);

   p_db.p_IDT_MSR_CRx_hashes = hash_from_CPU_data(p_db.p_IDT_MSR_CRx_array);

   if (hash_from_ex_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
         "CREATING DATABASE ERROR: EXCEPTION TABLE CAN\'T BE FOUND (skipping it)!\n");
      p_db.kernel_ex_table.p_hash = p_db.kernel_ex_table.p_size = 0x0;
      p_db.kernel_ex_table.p_addr = NULL;
   }

   if (hash_from_kernel_stext() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
         "CREATING DATABASE ERROR: HASH FROM _STEXT!\n");
      p_ret = P_LKRG_GENERAL_ERROR;
      goto p_create_database_out;
   }

   if (hash_from_kernel_rodata() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
         "CREATING DATABASE ERROR: _RODATA CAN\'T BE FOUND (skipping it)!\n");
      p_db.kernel_rodata.p_hash = p_db.kernel_rodata.p_size = 0x0;
      p_db.kernel_rodata.p_addr = NULL;
   }

   if (hash_from_iommu_table() != P_LKRG_SUCCESS) {
      p_print_log(P_LKRG_CRIT,
         "CREATING DATABASE ERROR: IOMMU TABLE CAN\'T BE FOUND (skipping it)!\n");
      p_db.kernel_iommu_table.p_hash = p_db.kernel_iommu_table.p_size = 0x0;
      p_db.kernel_iommu_table.p_addr = NULL;
   }

   /* We are heavly consuming module list here - take 'module_mutex' */
   mutex_lock(&module_mutex);

   /*
    * Memory allocation may fail... let's loop here!
    */
   while(p_kmod_hash(&p_db.p_module_list_nr,&p_db.p_module_list_array,
                     &p_db.p_module_kobj_nr,&p_db.p_module_kobj_array) != P_LKRG_SUCCESS);

   /* Release the 'module_mutex' */
   mutex_unlock(&module_mutex);

   p_db.p_module_list_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_list_array,
                                          (unsigned int)p_db.p_module_list_nr * sizeof(p_module_list_mem));
   p_db.p_module_kobj_hash = p_lkrg_fast_hash((unsigned char *)p_db.p_module_kobj_array,
                                          (unsigned int)p_db.p_module_kobj_nr * sizeof(p_module_kobj_mem));

   p_debug_log(P_LKRG_DBG,
          "p_module_list_hash => [0x%llx]\np_module_kobj_hash => [0x%llx]\n",
          p_db.p_module_list_hash,p_db.p_module_kobj_hash);

p_create_database_out:

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_create_database> (p_ret => %d)\n",p_ret);

   return p_ret;
}
