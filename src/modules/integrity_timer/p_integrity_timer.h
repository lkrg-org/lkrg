/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Integrity timer module
 *
 * Notes:
 *  - Periodically check critical system hashes using timer
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_INTEGRITY_TIMER_H
#define P_LKRG_INTEGRITY_TIMER_H

#define p_alloc_offload()      kmem_cache_alloc(p_offload_cache, GFP_ATOMIC)
#define p_free_offload(name)   kmem_cache_free(p_offload_cache, (void *)(name))

void p_check_integrity(struct work_struct *p_work);
void p_integrity_timer(void);
void p_offload_work(unsigned long p_timer);

int p_cmp_bytes(char *p_new, char *p_old, unsigned long p_size);

int p_offload_cache_init(void);
void p_offload_cache_delete(void);

extern struct timer_list p_timer;
extern spinlock_t p_db_lock;
extern unsigned long p_db_flags;
extern struct kmem_cache *p_offload_cache;

#endif
