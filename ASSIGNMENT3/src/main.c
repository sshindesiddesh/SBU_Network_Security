#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <in_args.h>
#include <pb_aes.h>

in_args_t in_args;

int main(int argc, char *argv[])
{
	int ret = parse_args(argc, argv);
	if (ret == -1) {
		printf(" Invalid Arguments\n");
		return 0;
	}
	print_args();
	char msg[] = "hey";
	uint8_t cipher[AES_BLOCK_SIZE];
	uint8_t plain[AES_BLOCK_SIZE];
	uint8_t *iv = get_iv();
	aes_ctr_encrypt(msg, cipher, iv);
	aes_ctr_encrypt(cipher, plain, iv);
	printf("\nPLAIN:%s\n", plain);
	return 0;
}
