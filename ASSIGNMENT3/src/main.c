#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <in_args.h>
#include <pb_aes.h>
#include <pb_sc.h>

#define BUF_SIZE	1024

in_args_t in_args;

int main(int argc, char *argv[])
{
	arg_flag = 0;
	int ret = parse_args(argc, argv);
	if (ret == -1) {
		printf(" Invalid Arguments\n");
		return 0;
	}
	print_args();

	/* Server */
	if (get_flag(ARG_FLAG_LPORT)) {
		uint8_t server_in_buf[1024] = {0};
		uint8_t server_out_buf[1024] = {0};
		int size;
		uint8_t *iv = get_iv();
		int server_sock = create_serv_sock(in_args.local_port);
		fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK);
		fcntl(server_sock,F_SETFL,O_NONBLOCK);
		while (1) {
			size = read(STDIN_FILENO, server_in_buf, BUF_SIZE);
			if (size > 0) {
				memcpy(iv, server_in_buf, 8);
				iv = get_iv();
				memcpy(server_out_buf, iv, 8);
				aes_ctr_encrypt(server_in_buf, server_out_buf + 8, iv, size);
				write(server_sock, server_out_buf, size + 8);
			}

			size = read(server_sock, server_in_buf, BUF_SIZE);
			if (size > 8) {
				memcpy(iv, server_in_buf, 8);
				aes_ctr_encrypt(server_in_buf + 8, server_out_buf, iv, size - 8);
				write(STDOUT_FILENO, server_out_buf, size - 8);
			}
		}
	/* Client */
	} else {
		char client_in_buf[1024] = {0};
		char client_out_buf[1024] = {0};
		int size;
		uint8_t *iv = get_iv();
		int client_fd = create_client_sock(8080, NULL);
		fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK);
		fcntl(client_fd,F_SETFL,O_NONBLOCK);
		while (1) {
			size = read(STDIN_FILENO, client_in_buf, BUF_SIZE);
			if (size > 0) {
				iv = get_iv();
				memcpy(client_out_buf, iv, 8);
				aes_ctr_encrypt(client_in_buf, client_out_buf + 8, iv, size);
				write(client_fd, client_out_buf, size + 8);
			}

			size = read(client_fd, client_in_buf, BUF_SIZE);
			if (size > 8) {
				memcpy(iv, client_in_buf, 8);
				aes_ctr_encrypt(client_in_buf + 8, client_out_buf, iv, size - 8);
				write(STDOUT_FILENO, client_out_buf, size - 8);
			}
		}
	}
	return 0;
}
