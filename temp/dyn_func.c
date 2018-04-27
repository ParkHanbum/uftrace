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
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
}
void _func2() {
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
}
void _func3() {
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
}
void _func4() {
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
}
void _func5() {
	gettimeofday(&val, NULL);
	printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
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
		_func1();
		_func2();
		_func3();
		_func4();
		_func5();
		_func6();
		if (count > 11) break;
		count++;
	}

	free(sleeptime);
}

int main()
{
	sleepfunc();
	return 0;
}
