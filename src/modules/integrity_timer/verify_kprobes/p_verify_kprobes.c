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

static int p_lkrg_dummy_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs);
static int p_lkrg_dummy_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs);

static char p_lkrg_dummy_kretprobe_state = 0;

static struct kretprobe p_lkrg_dummy_kretprobe = {
    .kp.symbol_name = "lkrg_dummy",
    .handler = p_lkrg_dummy_ret,
    .entry_handler = p_lkrg_dummy_entry,
};

#ifdef __clang__
__attribute__((optnone))
#else
__attribute__((optimize(0)))
#endif
static noinline int lkrg_dummy(int arg) {

   p_debug_log(P_LOG_DEBUG,
          "[lkrg_dummy] Argument value: [%d]\n",arg);

   /*
    * TODO:
    * We can verify integrity of the internal kprobe structures here
    */

   return arg+1;
}


int lkrg_verify_kprobes(void) {

   int p_ret = 0, ret = -1;

   if (!p_lkrg_dummy_kretprobe_state)
      return 0;

   /* Verify kprobes now */
   if ( (ret = lkrg_dummy(0)) != 3) {
      /* I'm hacked! ;( */
      p_print_log(P_LOG_ALERT, "DETECT: Kprobes: Don't work as intended (disabled?)");
      p_ret = -1;
   }
   p_print_log(P_LOG_WATCH, "lkrg_dummy returned %d vs. expected 3",ret);

   return p_ret;
}

static int p_lkrg_dummy_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs) {

   p_regs_set_arg1(p_regs, p_regs_get_arg1(p_regs) + 1);
   return 0;
}


static int p_lkrg_dummy_ret(struct kretprobe_instance *ri, struct pt_regs *p_regs) {

   p_regs_set_ret(p_regs, p_regs_get_ret(p_regs) + 1);
   return 0;
}

GENERATE_INSTALL_FUNC(lkrg_dummy)
