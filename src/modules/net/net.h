/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Remote logging module
 *
 * Timeline:
 *  - Initial implementation: October - November 2022
 *  - Forward-port and publication: February 2024
 *
 * Author:
 *  - Solar Designer
 *
 * Copyright:
 *  - 2022, Binarly
 *  - 2024, Solar Designer
 */

#ifndef LKRG_NET_H
#define LKRG_NET_H

#define LKRG_WITH_NET

#ifdef LKRG_WITH_NET

extern void lkrg_queue_net(void);

extern void lkrg_register_net(void);
extern void lkrg_deregister_net(void);

#else

#define lkrg_queue_net()
#define lkrg_register_net()
#define lkrg_deregister_net()

#endif

#endif
