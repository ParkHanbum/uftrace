#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

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
		trigger += 1;
		if (trigger > 3) {
			void* handle = dlopen("/home/m/test/uftrace/libtrigger.so", RTLD_LAZY);
			if (!handle) {
			    fputs (dlerror(), stdout);
			    exit(1);
			}
		}
		if (trigger > 8) {
			break;
		}
	}

	free(sleeptime);
}

int main()
{
	sleepfunc();
	return 0;
}
