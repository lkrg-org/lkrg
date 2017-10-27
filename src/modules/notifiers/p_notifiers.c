/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Notifiers module
 *
 * Notes:
 *  - Register multiple notifiers routines for integrity checking
 *  - Unfortunately, since Linux 4.10 there isn't idle notifier anymore :(
 *    Integrity check fired on idle state won't work in newer kernels.
 *    More information can be found here:
 *     => https://patchwork.kernel.org/patch/9435797/
 *
 * Timeline:
 *  - Created: 30.X.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static int p_idle_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
#endif
#ifdef CONFIG_CPU_FREQ
static int p_freq_transition_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
#endif
static int p_cpu_pm_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_netdevice_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_netevent_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
#if IS_ENABLED(CONFIG_IPV6)
static int p_inet6addr_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
#endif
static int p_inetaddr_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_taskfree_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_profile_event_exit_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_profile_event_munmap_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_usb_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);
static int p_acpi_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data);


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static struct notifier_block p_idle_notifier_nb = {
   .notifier_call = p_idle_notifier,
};
#endif

#ifdef CONFIG_CPU_FREQ
static struct notifier_block p_freq_transition_nb = {
   .notifier_call = p_freq_transition_notifier,
};
#endif

static struct notifier_block p_cpu_pm_notifier_nb = {
   .notifier_call = p_cpu_pm_notifier,
};

static struct notifier_block p_netdevice_notifier_nb = {
   .notifier_call = p_netdevice_notifier,
};

static struct notifier_block p_netevent_notifier_nb = {
   .notifier_call = p_netevent_notifier,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct notifier_block p_inet6addr_notifier_nb = {
   .notifier_call = p_inet6addr_notifier,
};
#endif

static struct notifier_block p_inetaddr_notifier_nb = {
   .notifier_call = p_inetaddr_notifier,
};

static struct notifier_block p_taskfree_notifier_nb = {
   .notifier_call = p_taskfree_notifier,
};

static struct notifier_block p_profile_event_exit_notifier_nb = {
   .notifier_call = p_profile_event_exit_notifier,
};

static struct notifier_block p_profile_event_munmap_notifier_nb = {
   .notifier_call = p_profile_event_munmap_notifier,
};

static struct notifier_block p_usb_notifier_nb = {
   .notifier_call = p_usb_notifier,
};

static struct notifier_block p_acpi_notifier_nb = {
   .notifier_call = p_acpi_notifier,
};


void p_register_notifiers(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_register_notifiers>\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
   idle_notifier_register(&p_idle_notifier_nb);
#endif
#ifdef CONFIG_CPU_FREQ
   cpufreq_register_notifier(&p_freq_transition_nb, CPUFREQ_TRANSITION_NOTIFIER);
#endif
   cpu_pm_register_notifier(&p_cpu_pm_notifier_nb);
   register_netdevice_notifier(&p_netdevice_notifier_nb);
   register_netevent_notifier(&p_netevent_notifier_nb);
#if IS_ENABLED(CONFIG_IPV6)
   register_inet6addr_notifier(&p_inet6addr_notifier_nb);
#endif
   register_inetaddr_notifier(&p_inetaddr_notifier_nb);
   task_handoff_register(&p_taskfree_notifier_nb);
   profile_event_register(PROFILE_TASK_EXIT, &p_profile_event_exit_notifier_nb);
   profile_event_register(PROFILE_MUNMAP, &p_profile_event_munmap_notifier_nb);
   usb_register_notify(&p_usb_notifier_nb);
   register_acpi_notifier(&p_acpi_notifier_nb);


// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_register_notifiers>\n");
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static int p_idle_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_idle_notifier>\n");

   /* 0.005% */
   P_TRY_OFFLOAD_NOTIFIER(P_M_SS_MORE_OFTEN_RATE, "<p_idle_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_idle_notifier>\n");

   return 0x0;
}
#endif

#ifdef CONFIG_CPU_FREQ
static int p_freq_transition_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_freq_transition_notifier>\n");

   /* 10% */
   P_TRY_OFFLOAD_NOTIFIER(P_RARE_RATE, "<p_freq_transition_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_freq_transition_notifier>\n");

   return 0x0;
}
#endif

static int p_cpu_pm_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_cpu_pm_notifier>\n");

   /* 10% */
   P_TRY_OFFLOAD_NOTIFIER(P_RARE_RATE, "<p_cpu_pm_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_cpu_pm_notifier>\n");

   return 0x0;
}

static int p_netdevice_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_netdevice_notifier>\n");

   /* 1% */
   P_TRY_OFFLOAD_NOTIFIER(P_OFTEN_RATE, "<p_netdevice_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_netdevice_notifier>\n");

   return 0x0;
}

static int p_netevent_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_netevent_notifier>\n");

   /* 5% */
   P_TRY_OFFLOAD_NOTIFIER(P_LESS_RARE_RATE, "<p_netevent_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_netevent_notifier>\n");

   return 0x0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int p_inet6addr_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_inet6addr_notifier>\n");

   /* 50% */
   P_TRY_OFFLOAD_NOTIFIER(P_SUPER_RARE_RATE, "<p_inet6addr_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_inet6addr_notifier>\n");

   return 0x0;
}
#endif

static int p_inetaddr_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_inetaddr_notifier>\n");

   /* 50% */
   P_TRY_OFFLOAD_NOTIFIER(P_SUPER_RARE_RATE, "<p_inetaddr_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_inetaddr_notifier>\n");

   return 0x0;
}

static int p_taskfree_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_taskfree_notifier>\n");

   /* 0.01% */
   P_TRY_OFFLOAD_NOTIFIER(P_SS_MORE_OFTEN_RATE, "<p_taskfree_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_taskfree_notifier>\n");

   return 0x0;
}

static int p_profile_event_exit_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_profile_event_exit_notifier>\n");

   /* 0.01% */
   P_TRY_OFFLOAD_NOTIFIER(P_SS_MORE_OFTEN_RATE, "<p_profile_event_exit_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_profile_event_exit_notifier>\n");

   return 0x0;
}

static int p_profile_event_munmap_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_profile_event_munmap_notifier>\n");

   /* 0.005%*/
   P_TRY_OFFLOAD_NOTIFIER(P_M_SS_MORE_OFTEN_RATE, "<p_profile_event_munmap_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_profile_event_munmap_notifier>\n");

   return 0x0;
}

static int p_usb_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_usb_notifier>\n");

   /* 50% */
   P_TRY_OFFLOAD_NOTIFIER(P_SUPER_RARE_RATE, "<p_usb_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_usb_notifier>\n");

   return 0x0;
}

static int p_acpi_notifier(struct notifier_block *p_nb, unsigned long p_val, void *p_data) {

// STRONG_DEBUG
   p_debug_notifier_log(
          "Entering function <p_acpi_notifier>\n");

   /* 50% */
   P_TRY_OFFLOAD_NOTIFIER(P_SUPER_RARE_RATE, "<p_acpi_notifier> Offloading integrity check\n");

// STRONG_DEBUG
   p_debug_notifier_log(
          "Leaving function <p_acpi_notifier>\n");

   return 0x0;
}


void p_deregister_notifiers(void) {

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_deregister_notifiers>\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
   idle_notifier_unregister(&p_idle_notifier_nb);
#endif
#ifdef CONFIG_CPU_FREQ
   cpufreq_unregister_notifier(&p_freq_transition_nb, CPUFREQ_TRANSITION_NOTIFIER);
#endif
   cpu_pm_unregister_notifier(&p_cpu_pm_notifier_nb);
   unregister_netdevice_notifier(&p_netdevice_notifier_nb);
   unregister_netevent_notifier(&p_netevent_notifier_nb);
#if IS_ENABLED(CONFIG_IPV6)
   unregister_inet6addr_notifier(&p_inet6addr_notifier_nb);
#endif
   unregister_inetaddr_notifier(&p_inetaddr_notifier_nb);
   task_handoff_unregister(&p_taskfree_notifier_nb);
   profile_event_unregister(PROFILE_TASK_EXIT, &p_profile_event_exit_notifier_nb);
   profile_event_unregister(PROFILE_MUNMAP, &p_profile_event_munmap_notifier_nb);
   usb_unregister_notify(&p_usb_notifier_nb);
   unregister_acpi_notifier(&p_acpi_notifier_nb);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_deregister_notifiers>\n");

}
