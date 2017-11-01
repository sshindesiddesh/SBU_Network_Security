#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include<in_args.h>

in_args_t in_args;

int main(int argc, char *argv[])
{
	parse_args(argc, argv);
	print_args();
	return 0;
}
