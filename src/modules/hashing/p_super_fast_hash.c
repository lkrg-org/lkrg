/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Hashing algorithm module - SuperFastHash
 *
 * Notes:
 *  - Algorithm from:
 *     *) http://azillionmonkeys.com/qed/hash.html
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

uint32_t p_super_fast_hash(const char *data, unsigned int len) {

   uint32_t hash = len, tmp;
   int rem;

   if (len == 0 || data == NULL)
      return 0;

   rem = len & 3;
   len >>= 2;

   /* Main loop */
   for (;len > 0; len--) {
      hash  += get16bits (data);
      tmp    = (get16bits (data+2) << 11) ^ hash;
      hash   = (hash << 16) ^ tmp;
      data  += 2*sizeof (uint16_t);
      hash  += hash >> 11;
   }

   /* Handle end cases */
   switch (rem) {
       case 3: hash += get16bits (data);
               hash ^= hash << 16;
               hash ^= data[sizeof (uint16_t)] << 18;
               hash += hash >> 11;
               break;
       case 2: hash += get16bits (data);
               hash ^= hash << 11;
               hash += hash >> 17;
               break;
       case 1: hash += *data;
               hash ^= hash << 10;
               hash += hash >> 1;
   }

   /* Force "avalanching" of final 127 bits */
   hash ^= hash << 3;
   hash += hash >> 5;
   hash ^= hash << 4;
   hash += hash >> 17;
   hash ^= hash << 25;
   hash += hash >> 6;

   return hash;
}
