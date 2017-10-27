/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Communication channel - sysctl interface
 *
 * Notes:
 *  - Allow administrator of the system to interact with LKRG via sysctl interface
 *
 * Timeline:
 *  - Created: 26.X.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_COMM_CHANNEL_SYSCTL_H
#define P_LKRG_COMM_CHANNEL_SYSCTL_H

extern struct ctl_table p_lkrg_sysctl_base[];
extern struct ctl_table p_lkrg_sysctl_table[];

int p_register_comm_channel(void);
void p_deregister_comm_channel(void);

#endif
