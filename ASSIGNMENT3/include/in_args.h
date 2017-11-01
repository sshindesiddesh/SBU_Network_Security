#ifndef _INARGS_H
#define _INARGS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

/* Generic Macros to set and clear bits in a variable */
#define set_flag(y) (arg_flag |= (1 << y))
#define get_flag(y) (arg_flag & (1 << y))
#define clr_flag(y) (arg_flag & ~(1 << y))

#define	ARG_FLAG_FILE		0
#define	ARG_FLAG_LPORT		1
#define ARG_FLAG_DNAME		2
#define	ARG_FLAG_DPORT		3

/* Structure to store input arguments */
typedef struct in_args_t {
	char *file;
	uint16_t local_port;
	char *dest_name;
	uint16_t dest_port;
	char *key;
} in_args_t;

int parse_args(int argc, char *argv[]);
void print_args();

#endif
