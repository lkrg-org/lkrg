/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Database module
 *    => Submodule - X86/AMD64 MSR specific data
 *
 * Notes:
 *  - X86/AMD64 MSR specific data
 *
 * Timeline:
 *  - Created: 28.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_MSR_H
#define P_LKRG_MSR_H

u64 p_read_msr(/*int p_cpu, */u32 p_arg);

#define P_MSR_READ_COUNT(x,y,z)              \
do {                                         \
   char p_tmp = x-1;                         \
   do {                                      \
      y = p_read_msr(z);                     \
   } while(!y && p_tmp--);                   \
} while(0)


#ifdef CONFIG_X86_64
 #define P_MSR_ASM_RET(val, low, high)     (((u64)(high) << 32) | (low))
 #define P_MSR_ASM_READ(val, low, high)     "=a" (low), "=d" (high)
#else
 #define P_MSR_ASM_RET(val, low, high)     (val)
 #define P_MSR_ASM_READ(val, low, high)     "=A" (val)
#endif

#endif
