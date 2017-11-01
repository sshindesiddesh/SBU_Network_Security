#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define S_PORT	8080

int main()
{
	struct sockaddr_in serv_addr;
	int client_fd, addrlen = sizeof(serv_addr);
	char client_buf[1024] = {0};

	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_fd == 0) {
		printf("Socket creation Error\n");
		return 0;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(S_PORT);

	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("CLient IP Address not supported Error\n");
		return 0;
	}

	if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("Client connection Error\n");
		return 0;
	}

	char *hello = "Hi Server";
	send(client_fd, hello, strlen(hello), 0);

	int valread = recv(client_fd, client_buf, 1024, 0);
	printf("Client received : %s\n", client_buf);

	return 0;
} 
