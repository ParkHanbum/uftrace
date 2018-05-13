#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <signal.h>

#define PR_FMT     "mcount-dynamic"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/env-file.h"

char *plthook = NULL;

/*
 * previous mcount_startup() the contructor.
 */
void pre_startup(void)
{
	int fd_envfile;

	/*
	 * the Process output is delayed for unknown reasons when using
	 * dynamic tracing. cannot found the reason of delay but below code
	 * can mitigation the symptom.
	 */
	setvbuf(stdout, NULL, _IONBF, 1024);
	setvbuf(stderr, NULL, _IONBF, 1024);

	fd_envfile = open_env_file();
	set_env_from_file(fd_envfile);

	plthook = getenv("UFTRACE_PLTHOOK");
	unsetenv("UFTRACE_PLTHOOK");
}

/*
 * configuration for dynamic tracing.
 */
void config_for_dynamic(void)
{
	char *pipefd_str;
	char *uftrace_pid_str;
	int uftrace_pid;
	struct stat statbuf;
	char fd_path[64];

	uftrace_pid_str = getenv("UFTRACE_PID");
	if (uftrace_pid_str) {
		uftrace_pid = strtol(uftrace_pid_str, NULL, 0);
		if (uftrace_pid == 0)
			pr_err_ns("Cannot parse UFTRACE_PID from environment.");
	}
	else {
		pr_err_ns("Cannot found UFTRACE_PID from environment.");
	}

	pipefd_str = getenv("UFTRACE_PIPE");
	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", uftrace_pid, pfd);
		pfd = open(fd_path, O_RDWR);
		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pfd = -1;
		}
	}
}

/*
 * post mcount_startup() the constructor.
 */
void post_startup(void)
{
	config_for_dynamic();

	// lazy plthook.
	if (plthook)
		setenv("UFTRACE_PLTHOOK", plthook, 1);

	bool nest_libcall = !!getenv("UFTRACE_NEST_LIBCALL");
	char *mcount_exename = read_exename();
	mcount_setup_plthook(mcount_exename, nest_libcall);
}


// TODO : make test and get the grade A+.

