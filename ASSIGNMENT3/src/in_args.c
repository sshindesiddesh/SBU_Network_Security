#include <in_args.h>

uint8_t arg_flag = 0;

extern in_args_t in_args;

void input_error()
{
	printf("Invalid Arguments\n");
	return;
}

/* Function to parse input arguments */
int parse_args(int argc, char *argv[])
{
	/* No argument is given */
	if (argc == 1)
		arg_flag = 0;

	int i = 0;
	char x = 0;
	for (i = 1; i < argc;) {
		if (argv[i][0] == '-' && (strlen(argv[i]) == 2)) {
			x = argv[i][1];
		} else {
				if (!argv[i]) {
					input_error();
					break;
				}
				in_args.dest_name = strdup(argv[i]);
				set_flag(ARG_FLAG_DNAME);
				i++;
				if (!argv[i]) {
					input_error();
					break;
				}
				in_args.dest_port = atoi(argv[i]);
				set_flag(ARG_FLAG_DPORT);
				i++;
				continue;
		}
		switch (x) {
			case 'l':
				if (!argv[i + 1]) {
					i += 1;
					input_error();
					break;
				}
				in_args.local_port = atoi(argv[i + 1]);
				set_flag(ARG_FLAG_LPORT);
				i += 2;
				break;
			case 'k':
				if (!argv[i + 1]) {
					i += 1;
					input_error();
					break;
				}
				in_args.file = strdup(argv[i + 1]);
				set_flag(ARG_FLAG_FILE);
				i += 2;
				break;
			default:
				input_error();
				i++;
				break;
		}
	}
}

void print_args()
{
	if (get_flag(ARG_FLAG_FILE)) {
		printf("File %s\n", in_args.file);
	}
	if (get_flag(ARG_FLAG_LPORT)) {
		printf("LPORT %d\n", in_args.local_port);
	}
	if(get_flag(ARG_FLAG_DNAME)) {
		printf("Dname %s\n", in_args.dest_name);
	}
	if (get_flag(ARG_FLAG_DPORT)) {
		printf("DPORT %d\n", in_args.dest_port);
	}
}
