#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <in_args.h>
#include <pb_aes.h>
#include <pb_sc.h>

in_args_t in_args;

int main(int argc, char *argv[])
{
	int ret = parse_args(argc, argv);
	if (ret == -1) {
		printf(" Invalid Arguments\n");
		return 0;
	}
	print_args();

#if 1
	/* Client */
	uint8_t client_in_buf[1024] = {0};
	uint8_t client_out_buf[1024] = {0};
	int client_fd = create_client_sock(8080);
	int size = 20;
	for (int i = 0; i < size; i++) {
		client_in_buf[i] = i;
	}
	uint8_t *iv = get_iv();
	memcpy(client_out_buf, iv, 8);
	aes_ctr_encrypt(client_in_buf, client_out_buf + 8, iv, size);
	write(client_fd, client_out_buf, size + 8);
	for (int i = 0; i < size + 8; i++) {
		printf ("%02x ", client_out_buf[i]);
		if (i != 0 && (i % 16 == 0))
			printf("\n");
	}
#else
	/*  Server */
	uint8_t server_in_buf[1024] = {0};
	uint8_t server_out_buf[1024] = {0};
	int server_sock = create_serv_sock(8080);
	int size = read(server_sock, server_in_buf, 1024);
	uint8_t iv[8];
	memcpy(iv, server_in_buf, 8);
	aes_ctr_encrypt(server_in_buf + 8, server_out_buf, iv, size - 8);
	for (int i = 0; i < size; i++) {
		printf ("%02x ", server_out_buf[i]);
		if (i != 0 && (i % 16 == 0))
			printf("\n");
	}
	printf("\n");
#endif
	return 0;
}
