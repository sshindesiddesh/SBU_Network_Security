#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <in_args.h>
#include <pb_aes.h>
#include <pb_sc.h>

#define TRANSP_SERVER	1
#define KEY_ENABLE	1

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
	//print_args();

	/* Server */
	if (get_flag(ARG_FLAG_LPORT)) {
		uint8_t server_in_buf[BUF_SIZE + 16] = {0};
		uint8_t server_out_buf[BUF_SIZE + 16] = {0};
		int size;
		uint8_t *iv = get_iv();
		int server_sock = create_serv_sock(in_args.local_port);
#if !TRANSP_SERVER
		int client_sock = create_client_sock(in_args.dest_port, in_args.dest_name);
		fcntl(client_sock, F_SETFL, O_NONBLOCK);
#endif
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(server_sock, F_SETFL, O_NONBLOCK);
		while (1) {
#if TRANSP_SERVER
			size = read(STDIN_FILENO, server_in_buf, BUF_SIZE);
			if (size > 0) {
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
#elif KEY_ENABLE
			size = read(server_sock, server_in_buf, BUF_SIZE);
			if (size > 0) {
				memcpy(iv, server_in_buf, 8);
				aes_ctr_encrypt(server_in_buf + 8, server_out_buf, iv, size - 8);
				write(client_sock, server_out_buf, size - 8);
				size = read(client_sock, server_in_buf, BUF_SIZE);
				if (size > 0) {
					iv = get_iv();
					memcpy(server_out_buf, iv, 8);
					aes_ctr_encrypt(server_in_buf, server_out_buf + 8, iv, size);
					write(server_sock, server_out_buf, size + 8);
				}
			}
#else
			size = read(server_sock, server_in_buf, BUF_SIZE);
			if (size > 0) {
				write(client_sock, server_in_buf, size);
				size = read(client_sock, server_in_buf, BUF_SIZE);
				if (size > 0) {
					write(server_sock, server_in_buf, size);
				}
			}
#endif
		}
	/* Client */
	} else {
		char client_in_buf[BUF_SIZE + 16];
		char client_out_buf[BUF_SIZE + 16];
		int size;
		uint8_t *iv = get_iv();
		int client_fd = create_client_sock(in_args.dest_port, in_args.dest_name);
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(client_fd, F_SETFL, O_NONBLOCK);
		while (1) {
#if KEY_ENABLE
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
#else
			size = read(STDIN_FILENO, client_in_buf, BUF_SIZE);
			if (size > 0) {
				write(client_fd, client_in_buf, size);
			}

			size = read(client_fd, client_in_buf, BUF_SIZE);
			if (size > 0) {
				write(STDOUT_FILENO, client_in_buf, size);
			}

#endif
		}
	}
	return 0;
}
