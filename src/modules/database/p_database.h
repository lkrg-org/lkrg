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

#ifndef P_LKRG_DATABASE_H
#define P_LKRG_DATABASE_H

/*
 * Memory block hash
 */
typedef struct p_hash_mem_block {

   long *p_addr;
   unsigned long p_size;
   uint64_t p_hash;

} p_hash_mem_block;

/*
 * CPU info structure:
 *
 * Keep track 'online/possible/present/active' CPUs.
 * Linux kernel keeps those data in CPU bitmask structure
 * which is extracet via following function:
 *
 * static inline int cpumask_test_cpu(int cpu, const struct cpumask *cpumask)
 *
 * That's why all variables have 'int' type
 */
typedef struct p_cpu_info {

   int online_CPUs;   // Might be active (because it's online) but it is NOT
                      // yet, so does NOT execute any task
   int possible_CPUs; // Physically possible CPUs handled by this kernel
   int present_CPUs;  // Currently available CPUs, but doesn't need to be used
                      // by kernel at this time. Value is dynamically updated
                      // when CPU is hotplug
   int active_CPUs;   // Currently active CPUs - can execute tasks

/*
 * "include/linux/cpumask.h"
 * ...
 * 34 #if NR_CPUS == 1
 * 35 #define nr_cpu_ids              1
 * 36 #else
 * 37 extern int nr_cpu_ids;
 * 38 #endif
 * ...
 */

   int p_nr_cpu_ids;  // Should be the same as possible_CPUs

} p_cpu_info;

#define P_CPU_OFFLINE 0
#define P_CPU_ONLINE 1

/*
 * Unique metadata per CPU arch. Currently, we support:
 *  - x86
 *  - arm64
 */
#include "arch/p_arch_metadata.h"

/*
 * Linux Kernel Module's specific structures...
 */
#include "../kmod/p_kmod.h"

/*
 * Dynamic *_JUMP_LABEL support (arch independent)
 */
#include "JUMP_LABEL/p_arch_jump_label_transform/p_arch_jump_label_transform.h"
#include "JUMP_LABEL/p_arch_jump_label_transform_apply/p_arch_jump_label_transform_apply.h"

enum p_jump_label_state {

   P_JUMP_LABEL_NONE,
   P_JUMP_LABEL_CORE_TEXT,
   P_JUMP_LABEL_MODULE_TEXT,
   P_JUMP_LABEL_WTF_STATE

};

/*
 * During *_JUMP_LABEL modification, we need to store information about its state.
 */
struct p_jump_label {

   enum p_jump_label_state p_state;
   struct module *p_mod;
   unsigned long *p_mod_mask;
   spinlock_t p_jl_lock;

};

/*
 * Main database structure containing:
 * - memory hashes
 * - Critical addresses
 * - CPU specific information
 */
typedef struct p_hash_database {

   /*
    * Information about CPUs in the system - CRITICAL !!!
    * Should be filled first.
    */
   p_cpu_info p_cpu;

   /*
    * Pointer to the dynamically allocated array - we don't know
    * how much memory do we need until we discover how many CPUs
    * do we have.
    *
    * Btw. our procedure must handle hot CPUs plug[in/out] as well !!!
    */
   p_CPU_metadata_hash_mem *p_CPU_metadata_array;

   /*
    * Hash from the all 'p_CPU_metadata_hash_mem' structures
    */
   uint64_t p_CPU_metadata_hashes;


   /*
    * Linux Kernel Modules in the system
    */
   unsigned int p_module_list_nr; // Count via walking through the list first
   unsigned int p_module_kobj_nr; // Count via walking through the KOBJs first

   /*
    * Linux Kernel Modules integrity
    */
   p_module_list_mem *p_module_list_array;
   uint64_t p_module_list_hash;
   p_module_kobj_mem *p_module_kobj_array;
   uint64_t p_module_kobj_hash;

   p_hash_mem_block kernel_stext;         // .text
   p_hash_mem_block kernel_rodata;        // .rodata
   p_hash_mem_block kernel_iommu_table;   // IOMMU table
   p_hash_mem_block kernel_ex_table;      // Exception tale
   struct p_jump_label p_jump_label;      // *_JUMP_LABEL state during modification

} p_hash_database;



extern p_hash_database p_db;
extern struct notifier_block p_cpu_notifier;

int hash_from_ex_table(void);
int hash_from_kernel_stext(void);
int hash_from_kernel_rodata(void);
int hash_from_iommu_table(void);

static inline void p_text_section_lock(void) {

   //jump_label_lock();
/*
   mutex_lock(P_SYM(p_jump_label_mutex));
   mutex_lock(P_SYM(p_text_mutex));
*/

   while (!mutex_trylock(P_SYM(p_jump_label_mutex)))
      schedule();
   mutex_lock(P_SYM(p_text_mutex));
}

static inline void p_text_section_unlock(void) {

   mutex_unlock(P_SYM(p_text_mutex));
   mutex_unlock(P_SYM(p_jump_label_mutex));

//   jump_label_unlock();
}

int p_create_database(void);
void p_get_cpus(p_cpu_info *p_arg);
int p_cmp_cpus(p_cpu_info *p_arg1, p_cpu_info *p_arg2);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
int p_cpu_callback(struct notifier_block *p_block, unsigned long p_action, void *p_hcpu);
#endif
int p_cpu_online_action(unsigned int p_cpu);
int p_cpu_dead_action(unsigned int p_cpu);
uint64_t hash_from_CPU_data(p_CPU_metadata_hash_mem *p_arg);



#endif
