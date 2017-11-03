#include <pb_sc.h>

int create_client_sock(int port)
{
	struct sockaddr_in serv_addr;
	int client_fd, addrlen = sizeof(serv_addr);

	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_fd == 0) {
		printf("Socket creation Error\n");
		return 0;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("CLient IP Address not supported Error\n");
		return 0;
	}

	if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("Client connection Error\n");
		return 0;
	}

	return client_fd;
} 
