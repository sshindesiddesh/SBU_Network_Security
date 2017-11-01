#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

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

int main()
{
	char *buf = read_key("key.txt");
	printf("Key is %s\n", buf);
	return 0;
}
