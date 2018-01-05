
#include <stdio.h>
#include "uftrace.h"

int command_dynamic(int argc, char *argv[], struct opts *opts) {
	int pid = opts->pid;
	if (pid < 1) {
		printf("You must specific process id(pid) to dynamic tracing.\n");
		exit(1); 
	}
	printf("implement here! : %d", opts->pid);
	return 0;	
}

