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

#define P_SUPER_RARE_RATE         2147483647    /*   50%     */
#define P_RARE_RATE               429496729     /*   10%     */
#define P_LESS_RARE_RATE          214748364     /*    5%     */
#define P_OFTEN_RATE              42949672      /*    1%     */
#define P_MORE_OFTEN_RATE         21474836      /*    0.5%   */
#define P_M_MORE_OFTEN_RATE       4294967       /*    0.1%   */
#define P_S_MORE_OFTEN_RATE       2147483       /*    0.05%  */
#define P_SS_MORE_OFTEN_RATE      429496        /*    0.01%  */
#define P_M_SS_MORE_OFTEN_RATE    21474         /*    0.005% */
#define P_S_SS_MORE_OFTEN_RATE    42949         /*    0.001% */

#define P_CHECK_RANDOM(x) ({ (get_random_int() < x) ? 1 : 0; })

#ifdef P_LKRG_DEBUG
#define P_TRY_OFFLOAD_NOTIFIER(p_arg1, p_arg2)        \
do {                                                  \
   if (P_CHECK_RANDOM(p_arg1)) {                      \
      p_print_log(P_LKRG_DBG, "%s", p_arg2);          \
      p_offload_work(0);                              \
   }                                                  \
} while(0)
#else
#define P_TRY_OFFLOAD_NOTIFIER(p_arg1, p_arg2)        \
do {                                                  \
   if (P_CHECK_RANDOM(p_arg1)) {                      \
      p_offload_work(0);                              \
   }                                                  \
} while(0)
#endif


void p_register_notifiers(void);
void p_deregister_notifiers(void);


#endif
