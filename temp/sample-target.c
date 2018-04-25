#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>


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
}

void sleepfunc()
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;

	pid_t pid = getpid();
	int trigger = 0;

	while(1)
	{
		printf("sleeping...%d \n", pid);
		nanosleep(sleeptime, NULL);
	}

	free(sleeptime);
}

int main()
{
	sleepfunc();
	return 0;
}
