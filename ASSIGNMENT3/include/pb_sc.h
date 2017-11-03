#ifndef _PB_SC_H
#define _PB_SC_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

int create_client_sock(int port, char *ip);
int create_serv_sock(int port);
#endif
