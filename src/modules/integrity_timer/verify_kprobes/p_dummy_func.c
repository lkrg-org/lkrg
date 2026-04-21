/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Integrity verification kprobe verification submodule
 *
 * Notes:
 *  - Verify if kprobes are enabled and correctly run
 *
 * Timeline:
 *  - Created: 30.XI.2022
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../../p_lkrg_main.h"

#ifdef __clang__
__attribute__((optnone))
#else
__attribute__((optimize(0)))
#endif
int lkrg_dummy(int arg) {

   p_debug_log(P_LOG_DEBUG,
          "[lkrg_dummy] Argument value: [%d]\n",arg);

   /*
    * TODO:
    * We can verify integrity of the internal kprobe structures here
    */

   return arg + 0x2200;
}
