
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "cryptodev.h"

#include <sys/types.h>
#include <sys/stat.h>

#define DATA_SIZE       16384
#define BLOCK_SIZE      16
#define KEY_SIZE        24

int main(int argc, char **argv)
{
	int fd = -1;
	char *filename;
	char error_str[100];

	filename = (argv[1] == NULL) ? "/dev/crypto" : argv[1];
	fd = open(filename, O_RDWR, 0);
	printf("DONE\n");
	if (fd < 0) {
		sprintf(error_str, "open %s", filename);
		perror(error_str);
		return 1;
	}

	

	return 0;
}
