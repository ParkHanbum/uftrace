#include "utils/env-file.h"

int create_env_file(void)
{
	int fd;

	fd = open(ENV_FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		pr_err(ERROR_CREATE_FILE);

	return fd;
}


int open_env_file(void)
{
	int fd;

	fd = open(ENV_FILE, O_RDONLY);
	if (fd < 0)
		pr_err(ERROR_OPEN_FILE);

	return fd;
}

/*
 * write a line to uftrace environment file with given argument fd.
 * a line contain key-value pair with separator '='.
 * like this,
 *
 * [example]
 * UFTRACE_PLTHOOK=1
 */
void set_env_to_file(int fd, char *key, char *value)
{
	int res;
	char buf[256];

	sprintf(buf, "%s", key);
	sprintf(buf + strlen(buf), "%s", "=");
	sprintf(buf + strlen(buf), "%s\n", value);
	res = write(fd, buf, strlen(buf));

	if (res < 0)
		pr_err_ns(ERROR_WHILE_WRITE);
}

void set_env_from_file(int fd)
{
	char buf[4096] = {0,};
	char key[1024] = {0,};
	char value[1024] = {0,};
	uint32_t key_index = 0;
	uint32_t value_index = 0;
	bool flag = true;
	int i, count;

	count = read(fd, buf, 4096);
	if (count < 0)
		pr_err(ERROR_READ_FILE);
	close(fd);

	for (i = 0; buf[i] != '\0' ; i++) {
		if (buf[i] == '\n') {
			pr_dbg3("ENVIRONMENT\t%s : %s\n", key, value);
			setenv(key, value, 1);
			flag = true;
			key_index = 0;
			memset(key, 0, sizeof(key));
			continue;
		}
		if (buf[i] == '=') {
			if (flag) {
				flag = false;
				value_index = 0;
				memset(value, 0, sizeof(value));
				continue;
			}
		}

		if (flag)
			key[key_index++] = buf[i];
		else
			value[value_index++] = buf[i];
	}
}
