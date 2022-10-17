/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Notifiers module
 *
 * Notes:
 *  - Register multiple notifiers routines for integrity checking
 *
 * Timeline:
 *  - Created: 30.X.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_NOTIFIERS_MODULE_H
#define P_LKRG_NOTIFIERS_MODULE_H

/* MAX unsigned int         4294967295  */
//#define P_OFTEN_RATE        5000000
//#define P_SUPER_OFTEN_RATE  250000
//#define P_RARE_RATE         80000000
//#define P_SUPER_RARE_RATE   3000000000

#define P_ALWAYS_RATE             4294967295U   /*  100%     */
#define P_SUPER_RARE_RATE         2147483647    /*   50%     */
#define P_RARE_RATE               429496729     /*   10%     */
#define P_LESS_RARE_RATE          214748364     /*    5%     */
#define P_OFTEN_RATE              42949672      /*    1%     */
#define P_MORE_OFTEN_RATE         21474836      /*    0.5%   */
#define P_M_MORE_OFTEN_RATE       4294967       /*    0.1%   */
#define P_S_MORE_OFTEN_RATE       2147483       /*    0.05%  */
#define P_SS_MORE_OFTEN_RATE      429496        /*    0.01%  */
#define P_M_SS_MORE_OFTEN_RATE    214748        /*    0.005% */
#define P_S_SS_MORE_OFTEN_RATE    42949         /*    0.001% */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define get_random_u32 get_random_int
#endif

#define P_CHECK_RANDOM(x) (get_random_u32() <= x)

#define P_TRY_OFFLOAD_NOTIFIER(rate, where)                                \
do {                                                                       \
   if (rate == P_ALWAYS_RATE || P_CHECK_RANDOM(rate)) {                    \
      p_debug_log(P_LOG_DEBUG, "%s: Offloading integrity check", where); \
      p_offload_work(0);                                                   \
   }                                                                       \
} while(0)

#define P_TRY_OFFLOAD_NOTIFIER_ALWAYS(where) P_TRY_OFFLOAD_NOTIFIER(P_ALWAYS_RATE, where)

void p_register_notifiers(void);
void p_deregister_notifiers(void);


#endif
