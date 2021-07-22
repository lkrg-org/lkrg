/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Hashing algorithm module - SipHash
 *
 * Notes:
 *  - Current Algorithm:
 *     *) https://131002.net/siphash/
 *  - Previous Algorithm from:
 *     *) http://azillionmonkeys.com/qed/hash.html
 *
 * Timeline:
 *  - Change SuperFastHash to SipHash
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#include "../../p_lkrg_main.h"

uint128_t p_global_siphash_key;

inline void p_lkrg_siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
                           uint8_t *out, const size_t outlen);

notrace uint64_t p_lkrg_fast_hash(const char *p_data, unsigned int p_len) {

   uint64_t p_tmp = 0;

   p_lkrg_siphash(p_data, p_len, (uint8_t *)&p_global_siphash_key, (uint8_t *)&p_tmp, sizeof(p_tmp));
   return p_tmp;
}

notrace inline void p_lkrg_siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
                                   uint8_t *out, const size_t outlen) {

   uint64_t v0 = 0x736f6d6570736575ULL;
   uint64_t v1 = 0x646f72616e646f6dULL;
   uint64_t v2 = 0x6c7967656e657261ULL;
   uint64_t v3 = 0x7465646279746573ULL;
   uint64_t k0 = U8TO64_LE(k);
   uint64_t k1 = U8TO64_LE(k + 8);
   uint64_t m;
   int i;
   const uint8_t *end = in + inlen - (inlen % sizeof(uint64_t));
   const int left = inlen & 7;
   uint64_t b = ((uint64_t)inlen) << 56;
   v3 ^= k1;
   v2 ^= k0;
   v1 ^= k1;
   v0 ^= k0;

   for (; in != end; in += 8) {
      m = U8TO64_LE(in);
      v3 ^= m;

      for (i = 0; i < cROUNDS; ++i)
         SIPROUND;

      v0 ^= m;
   }

   switch (left) {
      case 7:
         b |= ((uint64_t)in[6]) << 48;
         P_FALL_THROUGH;
      case 6:
         b |= ((uint64_t)in[5]) << 40;
         P_FALL_THROUGH;
      case 5:
         b |= ((uint64_t)in[4]) << 32;
         P_FALL_THROUGH;
      case 4:
         b |= ((uint64_t)in[3]) << 24;
         P_FALL_THROUGH;
      case 3:
         b |= ((uint64_t)in[2]) << 16;
         P_FALL_THROUGH;
      case 2:
         b |= ((uint64_t)in[1]) << 8;
         P_FALL_THROUGH;
      case 1:
         b |= ((uint64_t)in[0]);
         break;
      case 0:
         break;
   }

   v3 ^= b;

   for (i = 0; i < cROUNDS; ++i)
      SIPROUND;

   v0 ^= b;

   v2 ^= 0xff;

   for (i = 0; i < dROUNDS; ++i)
      SIPROUND;

   b = v0 ^ v1 ^ v2 ^ v3;
   U64TO8_LE(out, b);
}
