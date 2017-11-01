#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define S_PORT	8080

int main()
{
	struct sockaddr_in sockaddr;
	int server_fd, opt = 1, server_sock, addrlen = sizeof(sockaddr);
	char server_buf[1024] = {0};

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
	sockaddr.sin_port = htons(S_PORT);

	if (bind(server_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		printf("Server socket bind Error\n");
		return 0;
	}

	if (listen(server_fd, 5) < 0) {
		printf("Server listen Error\n");
		return 0;
	}

	if ((server_sock = accept(server_fd, (struct sockaddr *)&sockaddr, (socklen_t *)&addrlen)) < 0) {
		printf("Server accept Error\n");
		return 0;
	}

	int valread = recv(server_sock, server_buf, 1024, 0);
	printf("Server received : %s\n", server_buf);

	char *hello = "Hi Client";
	send(server_sock, hello, strlen(hello), 0);

	return 0;
} 
