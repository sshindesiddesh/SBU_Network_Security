#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <in_args.h>
#include <pb_aes.h>
#include <pb_sc.h>
#include <pthread.h>
#include <unistd.h>

/* Compile time flag to test transparent server. Should be set to 0 for pbproxy functionalionality. */
#define TRANSP_SERVER	0
/* Compile time flag to enable encrypted communication. */
#define KEY_ENABLE	1
/* Buffer Size */
#define BUF_SIZE	4096

in_args_t in_args;

/* Read IV */
uint8_t *read_iv(int fd)
{
	int size = 0, total = 0;
	uint8_t *iv = (uint8_t *)malloc(8);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	while (1) {
		total = read(fd, iv + size, 8);
		if (total > 0) {
			size += total;
		}
		if (size >= 8)
			break;
	}
	return iv;
}

/* Server Thread */
void *server_loop(void *p)
{
	int server_sock = (uint64_t)p;
#if 0
	printf("client SOCK %d discovered\n", server_sock);
#endif
	uint8_t server_in_buf[BUF_SIZE] = {0};
	uint8_t server_out_buf[BUF_SIZE] = {0};
	int size = 0, proto_size = 0, offset = 0;
	/* Read IV sent by the client */
	uint8_t *iv = read_iv(server_sock);
	/* Set the AES Key */
	set_aes_key();
	/* Make file descriptors non-blocking */
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(server_sock, F_SETFL, O_NONBLOCK);
#if !TRANSP_SERVER
	int client_sock = create_client_sock(in_args.dest_port, in_args.dest_name);
	fcntl(client_sock, F_SETFL, O_NONBLOCK);
#endif
	while (1) {
/* Encrypted communication to and from console */
#if TRANSP_SERVER
		/* Read from console and send to the client */
		while ((size = read(STDIN_FILENO, server_in_buf, BUF_SIZE)) >= 0) {
			write(server_sock, &size, sizeof(size));
			aes_ctr_encrypt(server_in_buf, server_out_buf, iv, size);
			write(server_sock, server_out_buf, size);
		}

		/* Read from client and send to the console */
		while ((size = read(server_sock, server_in_buf, sizeof(proto_size))) >= 0) {
			proto_size = *((int32_t *)server_in_buf);
			size = 0; offset = 0;
			while (1) {
				size = read(server_sock, server_in_buf + offset, proto_size - offset);
				if (size < 0)
					continue;
				offset += size;
				if (offset >= proto_size)
					break;
			}
			aes_ctr_encrypt(server_in_buf, server_out_buf, iv, proto_size);
			write(STDOUT_FILENO, server_out_buf, proto_size);
		}
/* Encrypted communication with the client and uncrpyted with the server (e.g. SSH) */
#elif KEY_ENABLE
		/* Read encrypted data from the client.
		 * Decrypt and send to the server.*/
		while ((size = read(server_sock, server_in_buf, sizeof(proto_size))) >= 0) {
			/* First 4 bytes is length */
			proto_size = *((int32_t *)server_in_buf);
			size = 0; offset = 0;
			while (1) {
				size = read(server_sock, server_in_buf + offset, proto_size - offset);
				if (size < 0)
					continue;
				offset += size;
				if (offset == proto_size)
					break;
			}
			/* Decrypt and send to the console */
			aes_ctr_encrypt(server_in_buf, server_out_buf, iv, proto_size);
			write(client_sock, server_out_buf, proto_size);
		}

		/* Read the data from server.
		 * Encrypt and send it to the client. */
		while ((size = read(client_sock, server_in_buf, BUF_SIZE)) >= 0) {
			/* send the read length */
			write(server_sock, &size, sizeof(size));
			/* Encrypt and send data */
			aes_ctr_encrypt(server_in_buf, server_out_buf, iv, size);
			write(server_sock, server_out_buf, size);
		}
#else
		while ((size = read(server_sock, server_in_buf, BUF_SIZE)) >= 0) {
			if (size > 0) {
				write(client_sock, server_in_buf, size);
			}
		}
		while ((size = read(client_sock, server_in_buf, BUF_SIZE)) >= 0) {
			if (size > 0) {
				write(server_sock, server_in_buf, size);
			}
		}
#endif
	}
}


/* Client Thread */
void client_loop()
{
	char client_in_buf[BUF_SIZE];
	char client_out_buf[BUF_SIZE];
	int size = 0, proto_size = 0, offset = 0;
	uint8_t *iv = get_iv();
	/* Set the AES key */
	set_aes_key();
	/* Create the client socket */
	int client_fd = create_client_sock(in_args.dest_port, in_args.dest_name);
	/* Send IV to the server */
	write(client_fd, iv, 8);
	/* Make file descriptors non-blocking */
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(client_fd, F_SETFL, O_NONBLOCK);
	while (1) {
/* Encrypted communication with the server */
#if KEY_ENABLE
		/* Read from console and write to proxy server */
		while ((size = read(STDIN_FILENO, client_in_buf, BUF_SIZE)) > 0) {
			/* send the read length */
			write(client_fd, &size, sizeof(size));
			/* Encrypt and send data */
			aes_ctr_encrypt(client_in_buf, client_out_buf, iv, size);
			write(client_fd, client_out_buf, size);
		}

		/* Read from the proxy server and write to the console */
		while ((size = read(client_fd, client_in_buf, sizeof(proto_size))) > 0) {
			/* First 4 bytes is length */
			proto_size = *((int32_t *)client_in_buf);
			size = 0; offset = 0;
			while (1) {
				size = read(client_fd, client_in_buf + offset, proto_size - offset);
				if (size < 0)
					continue;
				offset += size;
				if (offset >= proto_size)
					break;
			}
			/* Decrypt and send to the console */
			aes_ctr_encrypt(client_in_buf, client_out_buf, iv, proto_size);
			write(STDOUT_FILENO, client_out_buf, proto_size);
		}
/* Unencrypted communication with the server */
#else
		/* Read from console and write to proxy server */
		size = read(STDIN_FILENO, client_in_buf, BUF_SIZE);
		if (size > 0) {
			write(client_fd, client_in_buf, size);
		}

		/* Read from the proxy server and write to the console */
		size = read(client_fd, client_in_buf, BUF_SIZE);
		if (size > 0) {
			write(STDOUT_FILENO, client_in_buf, size);
		}

#endif
	}
}

int main(int argc, char *argv[])
{
	arg_flag = 0;
	int ret = parse_args(argc, argv);
	pthread_t tid;
	if (ret == -1) {
		printf(" Invalid Arguments\n");
		return 0;
	}
	/* print_args(); */
	if (!get_flag(ARG_FLAG_FILE) || !get_flag(ARG_FLAG_DNAME) || !get_flag(ARG_FLAG_DPORT)) {
		printf("Invalid Arguments\n");
		return 0;
	}

	/* Server */
	if (get_flag(ARG_FLAG_LPORT)) {
		uint64_t server_sock = create_serv_sock(in_args.local_port);
		while (1) {
			pthread_create(&tid, NULL, server_loop, (void *)server_sock);
			server_sock = serv_accept();
		}
	/* Client */
	} else {
		client_loop();
	}
	return 0;
}
