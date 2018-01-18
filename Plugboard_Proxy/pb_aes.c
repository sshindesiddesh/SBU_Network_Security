#include <in_args.h>
#include <pb_aes.h>

extern in_args_t in_args;

ctr_st st;

void init_ctr(ctr_st *st, uint8_t *iv)
{
	st->num = 0;
	memset(st->ecount, 0, 16);
	memset(st->ivec + 8, 0, 8);
	memcpy(st->ivec, iv, 8);
}

void aes_ctr_encrypt(uint8_t *msg, uint8_t *cipher)
{
	uint8_t iv[8];
	if (!RAND_bytes(iv, 8))
		printf("\nError in RAND_Bytes...\n");
	init_ctr(&st, iv);
	AES_KEY aes_key;
	char *key="qwe";
	AES_set_encrypt_key(key, 128, &aes_key);
	AES_ctr128_encrypt(msg, cipher, AES_BLOCK_SIZE, &aes_key, st.ivec, st.ecount, &st.num);
}

