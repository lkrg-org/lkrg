/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *    => submodule for dumping ARM specific metadata
 *
 * Notes:
 *  - Metadata can be different per CPU which makes it quite complicated...
 *    We need to run 'dumping' function on each CPU individually
 *
 *  - Linux kernel defines different types of CPUs:
 *    => online CPUs
 *    => possible CPUs
 *    => present CPUs
 *    => active CPUs
 *
 *    We are going to run procedure only on 'active CPUs' and different
 *    procedure is checking if number of active CPUs changes over time...
 *
 * Timeline:
 *  - Created: 09.X.2019
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../../p_lkrg_main.h"

#if defined(CONFIG_ARM)

/*
 * This function is independently executed by each active CPU.
 */
void p_dump_arm_metadata(void *_p_arg) {

   p_CPU_metadata_hash_mem *p_arg = _p_arg;
   int p_curr_cpu = 0xFFFFFFFF;

   /*
    * Get ID and lock - no preemtion.
    */
//   p_curr_cpu = get_cpu();
   p_curr_cpu = smp_processor_id();

   /*
    * To avoid multpile access to the same page from all CPUs
    * memory will be already zero'd
    */
//   memset(&p_arg[p_curr_cpu],0,sizeof(p_CPU_metadata_hash_mem));

   /*
    * First fill information about current CPU
    */
    p_arg[p_curr_cpu].p_cpu_id = p_curr_cpu;
    p_arg[p_curr_cpu].p_cpu_online = P_CPU_ONLINE;
}

#endif
