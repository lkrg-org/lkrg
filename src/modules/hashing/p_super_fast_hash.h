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

#ifndef P_LKRG_SUPERFASTHASH_H
#define P_LKRG_SUPERFASTHASH_H

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
   || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8) \
                     +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

uint32_t p_super_fast_hash(const char *data, unsigned int len);

#endif
