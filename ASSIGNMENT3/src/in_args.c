#include <in_args.h>

extern in_args_t in_args;

uint8_t arg_flag = 0;

void input_error()
{
	//printf("Invalid Arguments\n");
	return;
}

char *read_key(char *filename)
{
	FILE *fp = fopen(filename, "rb");
	char *key;
	uint32_t length;
	if (!fp) {
		printf("Key file read Error\n");
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	key = (char *)malloc(length);
	if (!key) {
		printf("Key memory allcation Error\n");
		fclose(fp);
		return NULL;
	}
	fread(key, 1, length, fp);
	fclose(fp);
	return key;
}

/* Function to parse input arguments */
int parse_args(int argc, char *argv[])
{
	/* No argument is given */
	if (argc == 1) {
		arg_flag = 0;
		return -1;
	}

	int i = 0;
	char x = 0;
	for (i = 1; i < argc;) {
		if (argv[i][0] == '-' && (strlen(argv[i]) == 2)) {
			x = argv[i][1];
		} else {
				if (!argv[i]) {
					input_error();
					return -1;
					break;
				}
				in_args.dest_name = strdup(argv[i]);
				set_flag(ARG_FLAG_DNAME);
				i++;
				if (!argv[i]) {
					input_error();
					return -1;
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
					return -1;
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
					return -1;
					break;
				}
				in_args.file = strdup(argv[i + 1]);
				in_args.key = read_key(in_args.file);
				set_flag(ARG_FLAG_FILE);
				i += 2;
				break;
			default:
				input_error();
				return -1;
				i++;
				break;
		}
	}
}

void print_args()
{
	if (get_flag(ARG_FLAG_FILE)) {
		printf("File %s\n", in_args.file);
		printf("Key %s\n", in_args.key);
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
