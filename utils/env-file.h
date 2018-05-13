#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <inttypes.h>
#include "utils/utils.h"

#define ENV_FILE  "/tmp/uftrace_environ_file"
#define ERROR_CREATE_FILE \
"Error occurred while write file.\n"

#define ERROR_OPEN_FILE \
"Error occurred while open file.\n"

#define ERROR_READ_FILE \
"Error occurred while read file.\n"

#define ERROR_WHILE_WRITE \
"Error occurred while write file.\n"				\
"[Trouble shooting]\n"						\
"Check a file named 'uftrace_environ_file' is existed "		\
"under '/tmp'.\n"

int create_env_file(void);
int open_env_file(void);
void set_env_to_file(int fd, char *key, char *value);
void set_env_from_file(int fd);
