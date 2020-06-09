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

struct p_isra_argument {

   const char *p_name;
   char *p_isra_name;

};

int p_try_isra_name(struct p_isra_argument *p_isra_arg);
long get_kallsyms_address(void);

#endif
