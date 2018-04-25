#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

__attribute__((constructor))
void so_main() {
	char* libname = "libmcount/libmcount-dynamic.so";
	char path[128] = {0, };
	char* current_path = getcwd(path, sizeof(path));	
	printf("Current working directory : %s\n", current_path);
	strncat(current_path, "/", 2);
	printf("Current working directory : %s\n", current_path);

	strncat(current_path, libname, strlen(libname)+1);
	printf("Current working directory : %s\n", current_path);

	printf("Library Path : %s\n", current_path);
	void* handle = dlopen(current_path, RTLD_LAZY);
	if (!handle) {
		printf("DLOPEN FAILED\n");	
		fputs(dlerror(), stdout);
		exit(1);
        }	
	
}


