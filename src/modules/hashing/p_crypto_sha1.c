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

#include "../../p_lkrg_main.h"

/*
 * Caller must free the buffer - kfree(*p_arg_out)
 */
char *p_sha1_hash(char **p_arg_out, const char *p_arg_in, unsigned int p_arg_len) {

   struct crypto_shash *p_tmp_sha1 = (struct crypto_shash *)-1;
   struct p_sdesc *p_tmp_sdesc = NULL;
   char p_tmp_sha1_hash[P_SHA1_SIZE];
   int p_ret = P_LKRG_SUCCESS;
   unsigned int p_tmp_size;

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Entering function <p_cpu_dead_action>\n");

   if (!p_arg_in || !p_arg_out || !p_arg_len || p_arg_len > 100) {
      *p_arg_out = NULL;
      p_ret = -1;
      goto p_sha1_hash_out;
   }

   memset(p_tmp_sha1_hash,0x0,P_SHA1_SIZE);
   p_tmp_sha1 = crypto_alloc_shash("sha1", 0, 0);
   if (IS_ERR(p_tmp_sha1)) {
      p_print_log(P_LKRG_CRIT,
             "SHA1: crypto_alloc_shash() error!\n");
      *p_arg_out = NULL;
      p_ret = -2;
      goto p_sha1_hash_out;
   }

   p_tmp_size = sizeof(struct shash_desc) + crypto_shash_descsize(p_tmp_sha1);
   if ( (p_tmp_sdesc = kmalloc(p_tmp_size, GFP_ATOMIC)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "SHA1: kmalloc() error!\n");
      *p_arg_out = NULL;
      p_ret = -3;
      goto p_sha1_hash_out;
   }

   p_tmp_sdesc->shash.tfm = p_tmp_sha1;
   p_tmp_sdesc->shash.flags = 0x0;

   if ( (p_ret = crypto_shash_init(&p_tmp_sdesc->shash)) != 0) {
      p_print_log(P_LKRG_CRIT,
             "SHA1: Could not init shash\n");
      *p_arg_out = NULL;
      p_ret = -4;
      goto p_sha1_hash_out;
   }

   if ( (p_ret = crypto_shash_update(&p_tmp_sdesc->shash, p_arg_in, p_arg_len)) != 0){
      p_print_log(P_LKRG_CRIT,
             "SHA1: Could not update with own string\n");
      *p_arg_out = NULL;
      p_ret = -5;
      goto p_sha1_hash_out;
   }

   if ( (p_ret = crypto_shash_final(&p_tmp_sdesc->shash, p_tmp_sha1_hash)) != 0) {
      p_print_log(P_LKRG_CRIT,
             "SHA1: Could not generate sha1 hash\n");
      *p_arg_out = NULL;
      p_ret = -6;
      goto p_sha1_hash_out;
   }

   if ( (*p_arg_out = kmalloc(P_SHA1_SIZE, GFP_ATOMIC)) == NULL) {
      p_print_log(P_LKRG_CRIT,
             "SHA1: kmalloc() SHA1_SIZE error!\n");
      *p_arg_out = NULL;
      p_ret = -7;
      goto p_sha1_hash_out;
   }

   memcpy(*p_arg_out, p_tmp_sha1_hash, P_SHA1_SIZE);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "[%d][%s]\n",p_arg_len,p_arg_in);
   p_debug_log(P_LKRG_STRONG_DBG,
          "SHA1 => [%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X]\n",
          p_tmp_sha1_hash[0],p_tmp_sha1_hash[1],p_tmp_sha1_hash[2],p_tmp_sha1_hash[3],
          p_tmp_sha1_hash[4],p_tmp_sha1_hash[5],p_tmp_sha1_hash[6],p_tmp_sha1_hash[7],
          p_tmp_sha1_hash[8],p_tmp_sha1_hash[9],p_tmp_sha1_hash[10],p_tmp_sha1_hash[11],
          p_tmp_sha1_hash[12],p_tmp_sha1_hash[13],p_tmp_sha1_hash[14],p_tmp_sha1_hash[15],
          p_tmp_sha1_hash[16],p_tmp_sha1_hash[17],p_tmp_sha1_hash[18],p_tmp_sha1_hash[19]
   );

p_sha1_hash_out:

   if (!IS_ERR(p_tmp_sha1))
      crypto_free_shash(p_tmp_sha1);
   if (p_tmp_sdesc)
      kfree(p_tmp_sdesc);

// STRONG_DEBUG
   p_debug_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_sha1_hash> ret => %d\n",p_ret);

   return *p_arg_out;
}
