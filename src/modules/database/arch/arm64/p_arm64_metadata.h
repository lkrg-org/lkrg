/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *    => Submodule - ARM64 specific metadata
 *
 * Notes:
 *  - None
 *
 * Timeline:
 *  - Created: 05.IV.2019
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_ARM64_METADATA_H
#define P_LKRG_ARM64_METADATA_H

/*
 * Each CPU in the system independently dump own critical data and save it using
 * following structure - it includes:
 *  - ...
 */
typedef struct p_CPU_metadata_hash_mem {

   /*
    * Some information about CPU to support hot-plug[in/out]
    */
   int p_cpu_id;
   char p_cpu_online; // 1 - online, 0 - offline

   char       p_MSR_marker;

} p_CPU_metadata_hash_mem;

void p_dump_arm64_metadata(void *_p_arg);
//void p_dump_arm64_metadata(p_CPU_metadata_hash_mem *p_arg);

#endif
