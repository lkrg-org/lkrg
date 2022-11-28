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
