#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>

typedef struct ctr_st {
	uint8_t ivec[16];
	uint32_t num;
	uint8_t ecount[16];
} ctr_st;

ctr_st st;

void init_ctr(ctr_st *st, uint8_t *iv)
{
	st->num = 0;
	memset(st->ecount, 0, 16);
	memset(st->ivec + 8, 0, 8);
	memcpy(st->ivec, iv, 8);
}

int main()
{
	uint8_t key[] = "thiskeyisverybad"; // It is 128bits though..
	uint8_t iv[8];
	if (!RAND_bytes(iv, 8))
		printf("\nError in RAND_Bytes...\n");
	init_ctr(&st, iv);
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);
	char msg[] = "hey";
	uint8_t cipher[AES_BLOCK_SIZE];
	uint8_t plain[AES_BLOCK_SIZE];
	AES_ctr128_encrypt((uint8_t *) msg, cipher, AES_BLOCK_SIZE, &aes_key, st.ivec, st.ecount, &st.num);
	init_ctr(&st, iv);
	AES_ctr128_encrypt(cipher, (uint8_t *) plain, AES_BLOCK_SIZE, &aes_key, st.ivec, st.ecount, &st.num);
	printf("\nPLAIN:%s\n", plain);
	return 0;
}
