/* This file  has functions for server handling. */

#include <pb_sc.h>

static struct sockaddr_in sockaddr;
static int server_fd;

/* Create server socket */
int create_serv_sock(int port)
{
	int opt = 1, server_sock;

	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_fd == 0) {
		printf("Socket creation Error\n");
		return 0;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		printf("Server setsockopt Error\n");
		return 0;
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	sockaddr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		printf("Server socket bind Error\n");
		return 0;
	}

	if (listen(server_fd, 20) < 0) {
		printf("Server listen Error\n");
		return 0;
	}

	server_sock = serv_accept();

	return server_sock;
}

/* Accept client connection */
int serv_accept()
{
	int addrlen = sizeof(sockaddr), server_sock;
	if ((server_sock = accept(server_fd, (struct sockaddr *)&sockaddr, (socklen_t *)&addrlen)) < 0) {
		printf("Server accept Error\n");
		return -1;
	}
	return server_sock;
}
