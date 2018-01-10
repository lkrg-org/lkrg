/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Integrity timer module - check Linux kernel .text section differences
 *
 * Notes:
 *  - Linux kernel is heavily consuming *_JUMP_LABEL (if enabled). Most of the
 *    Linux distributions provide kernel with these options compiled. It makes
 *    Linux kernel being self-modifying code. It is very troublesome for this
 *    project. We are relying on comparing hashes from the specific memory
 *    regions and by design self-midifications breaks this functionality.
 *    To mitigate the problem we do make special efford:
 *     - We keep a copy of the entire .text section made during module installation
 *     - If we detect that .text section for kernel was changed we try to find the
 *       offset where modifications was made. We use this offset to calculate the VA
 *       where modification was made. If modification happend because of the
 *       *_JUMP_LABEL options, originally long NOP was injected (5 bytes long) or
 *       already resolved relative 'jmp' instruction. If NOP is modified to 'jmp'
 *       the target is still pointing inside of the same function (symbol name).
 *       We decode jmp instruction to validate if the target is still pointing inside
 *       the same symbol name range, if yes it is most likely 'legit' modification.
 *       If 'jmp' instruction was changed, we only allow to be replaced by long NOP
 *       one. Also modification long NOP is only allowed to become 'jmp' pointing
 *       in the range of the same symbol name function.
 *       *WARN* It is still possible to find injected NOPs by *_JMP_LABEL and overwrte
 *              them using 'jmp' instruction and point to the random address at the
 *              same 'symbol name rage'. It allows attacker to create a rootkit based
 *              only on ROP. A few comments are needed here:
 *               - it is very difficult task to create fully functional rootkit based
 *                 only on 1-function ROP - but possible
 *               - at random point of time kernel WILL overwrite this modifications
 *                 anyway - so this won't be persistand modofications. Moreover, it
 *                 won't be deterministic so risk is very low
 *     - Every other modifications are banned
 *
 * Self-modifications are usually made via:
 *  - Tracepoints events
 *  - DO_ONCE() macro
 *
 * "whitelist" bytes:
 * - long nop:
 *    nopl   0x0(%rax,%rax,1):      0x0f    0x1f    0x44    0x00    0x00
 * - e.g. of relative jmp:
 *    jmpq   0xffffffff8168899e:    0xe9    0x9c    0x03    0x00    0x00
 *
 * "arch/x86/include/asm/jump_label.h" defines:
 *  17 #define JUMP_LABEL_NOP_SIZE 5
 *  18
 *  19 #ifdef CONFIG_X86_64
 *  20 # define STATIC_KEY_INIT_NOP P6_NOP5_ATOMIC
 *  21 #else
 *  22 # define STATIC_KEY_INIT_NOP GENERIC_NOP5_ATOMIC
 *  23 #endif
 *
 * Timeline:
 *  - Created: 28.VI.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef STATIC_KEY_INIT_NOP
 #ifdef CONFIG_X86_64
 # define STATIC_KEY_INIT_NOP P6_NOP5_ATOMIC
 #else
 # define STATIC_KEY_INIT_NOP GENERIC_NOP5_ATOMIC
 #endif
#endif

#if defined(CONFIG_MK7)
 #define P_ASM_NOP5_ATOMIC K7_NOP5_ATOMIC
#elif defined(CONFIG_X86_P6_NOP)
 #define P_ASM_NOP5_ATOMIC P6_NOP5_ATOMIC
#elif defined(CONFIG_X86_64)
 #define P_ASM_NOP5_ATOMIC K8_NOP5_ATOMIC
#else
 #define P_ASM_NOP5_ATOMIC GENERIC_NOP5_ATOMIC
#endif

char p_white_nop[JUMP_LABEL_NOP_SIZE] = { STATIC_KEY_INIT_NOP };
char p_white_nop2[JUMP_LABEL_NOP_SIZE] = { P_ASM_NOP5_ATOMIC };

/*
#define VALUE_TO_STRING(x) #x
#define VALUE(x) VALUE_TO_STRING(x)
#define VAR_NAME_VALUE(var) #var "="  VALUE(var)

#pragma message(VAR_NAME_VALUE( __stringify(P_ASM_NOP5_ATOMIC)))
*/

int p_cmp_bytes(char *p_new, char *p_old, unsigned long p_size) {

   unsigned long p_tmp;
   unsigned int *p_val; // 'jmp' arg
   char p_sym1[KSYM_SYMBOL_LEN]; // symbol name of the original VA
   char p_sym2[KSYM_SYMBOL_LEN]; // symbol name of the destination 'jmp' VA
   unsigned long p_VA1; // Original VA
   unsigned long p_VA2; // destination 'jmp' VA
   unsigned int p_cnt; // counter
   char p_flag;
   size_t p_len; // length of the symbol name

   memset(p_sym1,0x0,KSYM_SYMBOL_LEN);
   memset(p_sym2,0x0,KSYM_SYMBOL_LEN);

   for (p_tmp = 0x0; p_tmp < p_size-JUMP_LABEL_NOP_SIZE; p_tmp++) {
      if (p_new[p_tmp] != p_old[p_tmp]) {

         // STRONG_DEBUG
         p_debug_log(P_LKRG_STRONG_DBG,
//         p_print_log(P_LKRG_CRIT,
                                        "Offset[0x%lx] old[0x%x] new[0x%x]\n",
                                        p_tmp,
                                        (unsigned int)(p_old[p_tmp] & 0xFF),
                                        (unsigned int)(p_new[p_tmp] & 0xFF));
         // STRONG_DEBUG
         p_debug_log(P_LKRG_STRONG_DBG,
//         p_print_log(P_LKRG_CRIT,
                                  "old[0x%x] old+1[0x%x] old+2[0x%x] old+3[0x%x] old+4[0x%x]\n",
                                  p_old[p_tmp] & 0xFF,p_old[p_tmp+1] & 0xFF,p_old[p_tmp+2] & 0xFF,
                                  p_old[p_tmp+3] & 0xFF, p_old[p_tmp+4] & 0xFF);

         // STRONG_DEBUG
         p_debug_log(P_LKRG_STRONG_DBG,
//         p_print_log(P_LKRG_CRIT,
                                  "new[0x%x] new+1[0x%x] new+2[0x%x] new+3[0x%x] new+4[0x%x]\n",
                                  p_new[p_tmp] & 0xFF, p_new[p_tmp+1] & 0xFF, p_new[p_tmp+2] & 0xFF,
                                  p_new[p_tmp+3] & 0xFF, p_new[p_tmp+4] & 0xFF);

         /* OK, we have found difference, let's check if this is "whitelist" modifications */
/*
         if ((p_old[p_tmp] & 0xFF) == 0x0f && (p_old[p_tmp+1] & 0xFF) == 0x1f &&    // Is long NOP
             (p_old[p_tmp+2] & 0xFF) == 0x44 && (p_old[p_tmp+3] & 0xFF) == 0x00 &&  // was overwritten?
             (p_old[p_tmp+4] & 0xFF) == 0x00) {
*/

         p_flag = 0x0;
         if ( (p_old[p_tmp] & 0xFF) == (p_white_nop[0x0] & 0xFF) ) { // NOP -> JMP/0xcc ?
            for (p_cnt = 0x1; p_cnt < JUMP_LABEL_NOP_SIZE; p_cnt++) {
               if ( (p_old[p_tmp+p_cnt] & 0xFF) != (p_white_nop[p_cnt] & 0xFF) ) {
                  p_flag = 0x1;
                  break;
               }
            }
            p_flag = (p_flag) ? 0x0 : 0x1;
         } else if ( (p_new[p_tmp] & 0xFF) == (p_white_nop[0x0] & 0xFF) ) { // JMP/0xcc -> NOP ?
            for (p_cnt = 0x1; p_cnt < JUMP_LABEL_NOP_SIZE; p_cnt++) {
               if ( (p_new[p_tmp+p_cnt] & 0xFF) != (p_white_nop[p_cnt] & 0xFF) ) {
                  p_flag = 0x1;
                  break;
               }
            }
            p_flag = (p_flag) ? 0x0 : 0x2;
         }

         if (!p_flag) { // it could be other type of NOP...
            if ( (p_old[p_tmp] & 0xFF) == (p_white_nop2[0x0] & 0xFF) ) { // NOP -> JMP/0xcc ?
               for (p_cnt = 0x1; p_cnt < JUMP_LABEL_NOP_SIZE; p_cnt++) {
                  if ( (p_old[p_tmp+p_cnt] & 0xFF) != (p_white_nop2[p_cnt] & 0xFF) ) {
                     p_flag = 0x1;
                     break;
                  }
               }
               p_flag = (p_flag) ? 0x0 : 0x1;
            } else if ( (p_new[p_tmp] & 0xFF) == (p_white_nop2[0x0] & 0xFF) ) { // JMP/0xcc -> NOP ?
               for (p_cnt = 0x1; p_cnt < JUMP_LABEL_NOP_SIZE; p_cnt++) {
                  if ( (p_new[p_tmp+p_cnt] & 0xFF) != (p_white_nop2[p_cnt] & 0xFF) ) {
                     p_flag = 0x1;
                     break;
                  }
               }
               p_flag = (p_flag) ? 0x0 : 0x2;
            }
         }

         if (p_flag == 0x1) { // NOP -> JMP/0xcc
            /*
             * OK, so we know long NOP was overwritten... we only allow modification
             * to relative jmp pointing to exactly the same function... Let's check
             */
            if ( (p_new[p_tmp] & 0xFF) == 0xe9) { // Is it 'jmp' ?
               p_val = (unsigned int *)&p_new[p_tmp+0x1]; // 'jmp' arg
               p_VA1 = (unsigned long) &p_new[p_tmp]; // original VA
               p_VA2 = (unsigned long) p_VA1 + 5 + *p_val; // destination VA
               sprint_symbol_no_offset(p_sym1,p_VA1); // symbol name for original VA
               sprint_symbol_no_offset(p_sym2,p_VA2); // symbol name for destination VA

               // DEBUG
               p_debug_log(P_LKRG_DBG,
                           "[NOP->JMP] p_val[0x%x] p_VA1[0x%lx] p_VA2[0x%lx] p_sym1[%s] p_sym2[%s]\n",
                           *p_val,p_VA1,p_VA2,p_sym1,p_sym2);

               p_len = strlen(p_sym1);
               if (p_len != strlen(p_sym2))
                  return -1; // Lenght is different so for sure this is not the same symbol!

               if (strncmp(p_sym1,p_sym2,p_len))
                  return -1; // This is not the same symbol even length is the same...

               // Shout be P_LKRG_WARN?
               p_print_log(P_LKRG_INFO, "Detected legit self-modification in core linux .text "
                                        "section in VA[0x%lx] function [%s] - tracepoints?\n",
                                        p_VA1,p_sym1);

               /*
                * Let's modify dynamicaly copy of the vmlinux image. We know that current modification
                * is "whitelisted" and if it returns to the original values we need to be able
                * to detect that. If we dynamically updating copy of vmlinux image it is possible
                * to have 'half-baked cake'. If further modifications are NOT "whitelisted" but previous
                * one was, we return immediately with not fully modified copy of vmlinux. But that's
                * OK. If further modifications are NOT valid it means system was fully compromised
                * and non of the data should be trusted. We should PANIC the kernel... or not if
                * administrator of the system decided otherwise...
                */
               p_old[p_tmp] = p_new[p_tmp];
               p_old[p_tmp+1] = p_new[p_tmp+1];
               p_old[p_tmp+2] = p_new[p_tmp+2];
               p_old[p_tmp+3] = p_new[p_tmp+3];
               p_old[p_tmp+4] = p_new[p_tmp+4];

               p_tmp += 4; // Let's continue our checks... first, do increase indexer!
               continue;

            } else if ( ((p_new[p_tmp] & 0xFF) == 0xcc) && // Is it int3 ?
//                        ((p_new[p_tmp+1] & 0xFF) == 0xad) && // rest of the bytes can't be random...
                        ( ((p_new[p_tmp+2] & 0xFF) == 0x00) ||
                          ((p_new[p_tmp+2] & 0xFF) == (p_white_nop[0x2] & 0xFF)) ||
                          ((p_new[p_tmp+2] & 0xFF) == (p_white_nop2[0x2] & 0xFF))) && // rest of the bytes can't be random...
                        ( ((p_new[p_tmp+3] & 0xFF) == 0x00) ||
                          ((p_new[p_tmp+3] & 0xFF) == (p_white_nop[0x3] & 0xFF)) ||
                          ((p_new[p_tmp+3] & 0xFF) == (p_white_nop2[0x3] & 0xFF))) && // rest of the bytes can't be random...
                        ( ((p_new[p_tmp+4] & 0xFF) == 0x00) ||
                          ((p_new[p_tmp+4] & 0xFF) == (p_white_nop[0x4] & 0xFF)) ||
                          ((p_new[p_tmp+4] & 0xFF) == (p_white_nop2[0x4] & 0xFF)))) { // rest of the bytes can't be random...

               // DEBUG
               p_debug_log(P_LKRG_DBG,
                           "[NOP->0xCC] p_old[0x%lx]{0x%x} -> p_new[0x%lx] => 0x%x\n",
                                                          p_tmp,p_old[p_tmp],p_tmp,p_new[p_tmp]);

               /*
                * Let's modify dynamicaly copy of the vmlinux image. We know that current modification
                * is "whitelisted" and if it returns to the original values we need to be able
                * to detect that. If we dynamically updating copy of vmlinux image it is possible
                * to have 'half-baked cake'. If further modifications are NOT "whitelisted" but previous
                * one was, we return immediately with not fully modified copy of vmlinux. But that's
                * OK. If further modifications are NOT valid it means system was fully compromised
                * and non of the data should be trusted. We should PANIC the kernel... or not if
                * administrator of the system decided otherwise...
                */
               p_old[p_tmp] = p_new[p_tmp];
               p_old[p_tmp+1] = p_new[p_tmp+1];
               p_old[p_tmp+2] = p_new[p_tmp+2];
               p_old[p_tmp+3] = p_new[p_tmp+3];
               p_old[p_tmp+4] = p_new[p_tmp+4];

               p_tmp += 4; // Let's continue our checks... first, do increase indexer!
               continue;

            } else { // We do not allow any other modifications...
               return -1; // We do not need to check further modifications because
                          // this one is malicious so entire system might compromised
                          // anyway - regardless if further modifications are "whitelisted"
                          // or not
            }
         } else if (p_flag == 0x2) { // JMP/0xcc -> NOP

            /*
             * Let's check if original 'jmp' was in the range of the same symbol name
             * If not, this is very weird situation... should never happens!
             */

            if ((p_old[p_tmp] & 0xFF) == 0xe9) {
               p_val = (unsigned int *)&p_old[p_tmp+0x1]; // 'jmp' arg
               p_VA1 = (unsigned long) &p_new[p_tmp]; // original VA
               p_VA2 = (unsigned long) p_VA1 + 5 + *p_val; // destination VA
               sprint_symbol_no_offset(p_sym1,p_VA1); // symbol name for original VA
               sprint_symbol_no_offset(p_sym2,p_VA2); // symbol name for destination VA

               // DEBUG
               p_debug_log(P_LKRG_DBG,
                           "[JMP->NOP] p_val[0x%x] p_VA1[0x%lx] p_VA2[0x%lx] p_sym1[%s] p_sym2[%s]\n",
                           *p_val,p_VA1,p_VA2,p_sym1,p_sym2);

               p_len = strlen(p_sym1);
               if (p_len != strlen(p_sym2)) {
                  p_print_log(P_LKRG_CRIT,"[WEIRD!] Kernel overwrote JMP instruction pointing "
                                          "not in the same function via NOP - should NOT happens!\n");
                  // Weird! Lenght is different so for sure this is not the same symbol!
                  //return -1; <- let's continue checks!
               }

               if (strncmp(p_sym1,p_sym2,p_len)) {
                  p_print_log(P_LKRG_CRIT,"[WEIRD!] Kernel overwrote JMP instruction pointing "
                                          "not in the same function via NOP - should NOT happens!\n");
                  // Weird! This is not the same symbol even length is the same...
                  //return -1; <- let's continue checks!
               }

               // Shout be P_LKRG_WARN?
               p_print_log(P_LKRG_INFO, "Detected legit self-modification in core linux .text "
                                        "section in VA[0x%lx] function [%s] - tracepoints?\n",
                                        p_VA1,p_sym1);

               /*
                * Let's modify dynamicaly copy of the vmlinux image. We know that current modification
                * is "whitelisted" and if it returns to the original values we need to be able
                * to detect that. If we dynamically updating copy of vmlinux image it is possible
                * to have 'half-baked cake'. If further modifications are NOT "whitelisted" but previous
                * one was, we return immediately with not fully modified copy of vmlinux. But that's
                * OK. If further modifications are NOT valid it means system was fully compromised
                * and non of the data should be trusted. We should PANIC the kernel... or not if
                * administrator of the system decided otherwise...
                */
               p_old[p_tmp] = p_new[p_tmp];
               p_old[p_tmp+1] = p_new[p_tmp+1];
               p_old[p_tmp+2] = p_new[p_tmp+2];
               p_old[p_tmp+3] = p_new[p_tmp+3];
               p_old[p_tmp+4] = p_new[p_tmp+4];

               p_tmp += 4; // Let's continue our checks... first, do increase indexer!
               continue;

            } else if ( ((p_old[p_tmp] & 0xFF) == 0xcc) && // Is it int3 ?
//                        ((p_old[p_tmp+1] & 0xFF) == 0xad) && // rest of the bytes can't be random...
                        ( ((p_old[p_tmp+2] & 0xFF) == 0x00) ||
                          ((p_old[p_tmp+2] & 0xFF) == (p_white_nop[0x2] & 0xFF)) ||
                          ((p_old[p_tmp+2] & 0xFF) == (p_white_nop2[0x2] & 0xFF))) && // rest of the bytes can't be random...
                        ( ((p_old[p_tmp+3] & 0xFF) == 0x00) ||
                          ((p_old[p_tmp+3] & 0xFF) == (p_white_nop[0x3] & 0xFF)) ||
                          ((p_old[p_tmp+3] & 0xFF) == (p_white_nop2[0x3] & 0xFF))) && // rest of the bytes can't be random...
                        ( ((p_old[p_tmp+4] & 0xFF) == 0x00) ||
                          ((p_old[p_tmp+4] & 0xFF) == (p_white_nop[0x4] & 0xFF)) ||
                          ((p_old[p_tmp+4] & 0xFF) == (p_white_nop2[0x4] & 0xFF)))) { // rest of the bytes can't be random...


               // DEBUG
               p_debug_log(P_LKRG_DBG,
                           "[0xCC->NOP] p_old[0x%lx]{0x%x} -> p_new[0x%lx] => 0x%x\n",
                                                          p_tmp,p_old[p_tmp],p_tmp,p_new[p_tmp]);

               /*
                * Let's modify dynamicaly copy of the vmlinux image. We know that current modification
                * is "whitelisted" and if it returns to the original values we need to be able
                * to detect that. If we dynamically updating copy of vmlinux image it is possible
                * to have 'half-baked cake'. If further modifications are NOT "whitelisted" but previous
                * one was, we return immediately with not fully modified copy of vmlinux. But that's
                * OK. If further modifications are NOT valid it means system was fully compromised
                * and non of the data should be trusted. We should PANIC the kernel... or not if
                * administrator of the system decided otherwise...
                */
               p_old[p_tmp] = p_new[p_tmp];
               p_old[p_tmp+1] = p_new[p_tmp+1];
               p_old[p_tmp+2] = p_new[p_tmp+2];
               p_old[p_tmp+3] = p_new[p_tmp+3];
               p_old[p_tmp+4] = p_new[p_tmp+4];

               p_tmp += 4; // Let's continue our checks... first, do increase indexer!
               continue;

            } else { // We do not allow any other modifications...
               return -1; // We do not need to check further modifications because
                          // this one is malicious so entire system might compromised
                          // anyway - regardless if further modifications are "whitelisted"
                          // or not
            }
         } else {
            return -1; // We do not need to check further modifications because
                       // this one is malicious so entire system might compromised
                       // anyway - regardless if further modifications are "whitelisted"
                       // or not
         }
      }
   }

   return 0x0;
}




