/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Hashing algorithm module - SHA1 via crypto API
 *
 * Notes:
 *  - SHA1 via crypto API
 *
 * Timeline:
 *  - Created: 11.IV.2017
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_CRYPTOAPI_SHA1_H
#define P_LKRG_CRYPTOAPI_SHA1_H

#define P_SHA1_SIZE 20

struct p_sdesc {
   struct shash_desc shash;
   char ctx[];
};

char *p_sha1_hash(char **p_arg_out, const char *p_arg_in, unsigned int p_arg_len);

#endif
