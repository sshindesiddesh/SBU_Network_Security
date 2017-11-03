#ifndef _PBAES_H
#define _PBAES_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <in_args.h>
#include <string.h>
#define IV_SIZE		16

typedef struct ctr_st {
	uint8_t ivec[16];
	uint32_t num;
	uint8_t ecount[16];
} ctr_st;

void init_ctr(ctr_st *st, uint8_t *iv);
void aes_ctr_encrypt(uint8_t *msg, uint8_t *cipher, uint8_t *iv, int size);
uint8_t *get_iv();

#endif
