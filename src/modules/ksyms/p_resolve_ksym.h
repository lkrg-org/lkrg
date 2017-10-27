/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Resolve kernel symbols
 *
 * Notes:
 *  - We try to 'resolve' old-school Linux kernel function for
 *    resolving symbols on run-time
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_RESOLVE_KSYM_H
#define P_LKRG_RESOLVE_KSYM_H

extern unsigned long (*p_kallsyms_lookup_name)(const char *name);

long get_kallsyms_address(void);

#endif
