#include <pb_sc.h>

int create_client_sock(int port, char *ip)
{
	struct sockaddr_in serv_addr;
	struct hostent *serv_host = NULL;
	int client_fd, addrlen = sizeof(serv_addr);

	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_fd == 0) {
		printf("Socket creation Error\n");
		return -1;
	}

	if (ip) {
		if ((serv_host = gethostbyname(ip)) == NULL) {
			printf("Hostname Error\n");
			return -1;
		}
		memcpy(&serv_addr.sin_addr.s_addr, serv_host->h_addr, serv_host->h_length);
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("CLient IP Address not supported Error\n");
		return -1;
	}

	if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("Client connection Error\n");
		return -1;
	}

	return client_fd;
} 
