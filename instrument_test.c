#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <dlfcn.h>

struct timeval val;
struct timespec* sleeptime;
int count = 0;

void _func1() {
}
void _func2() {
}
void _func3() {
}
void _func4() {
}
void _func5() {
}
void _func6() {
	nanosleep(sleeptime, NULL);
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
}

void sleepfunc()
{
	sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;

	pid_t pid = getpid();
	int trigger = 0;

	while(1)
	{
		printf("sleeping...%d \n", pid);
		_func5();
		_func6();
		count++;
	}

	free(sleeptime);
}

int main()
{
	dlopen("/home/m/test/uftrace/libmcount/libmcount-dynamic.so", RTLD_LAZY);
	sleepfunc();
	return 0;
}
