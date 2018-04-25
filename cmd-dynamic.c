#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <fnmatch.h>
#include <linux/limits.h>
#include <sys/ptrace.h>
#include <sys/time.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/filter.h"
#include "utils/kernel.h"
#include "utils/perf.h"
#include "utils/debugger.h"

#define SHMEM_NAME_SIZE (64 - (int)sizeof(struct list_head))

extern void record_mmap_file(const char *dirname, char *sess_id, int bufsize);
extern void flush_old_shmem(const char *dirname, int tid, int bufsize);
extern void add_tid_list(int pid, int tid);

struct shmem_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
};

static LIST_HEAD(shmem_list_head);
static LIST_HEAD(shmem_need_unlink);

struct buf_list {
	struct list_head list;
	int tid;
	void *shmem_buf;
};

static LIST_HEAD(buf_free_list);
static LIST_HEAD(buf_write_list);

/* currently active writers */
static LIST_HEAD(writer_list);


static bool has_perf_event;
static char absolute_file_path[PATH_MAX];

static bool check_linux_perf_event(char *events)
{
        char *str, *tmp, *evt;
        bool found = false;

        if (events == NULL)
                return false;

        str = tmp = xstrdup(events);

        evt = strtok(tmp, ";");
        while (evt) {
                if (fnmatch(evt, "linux:schedule", 0) == 0) {
                        found = true;
                        break;
                }
                evt = strtok(NULL, ";");
        }

        free(str);
        return found;
}

static char *build_debug_domain_string(void)
{
        int i, d;
        static char domain[2*DBG_DOMAIN_MAX + 1];

        for (i = 0, d = 0; d < DBG_DOMAIN_MAX; d++) {
                if (dbg_domain[d]) {
                        domain[i++] = DBG_DOMAIN_STR[d];
                        domain[i++] = dbg_domain[d] + '0';
                }
        }
        domain[i] = '\0';

        return domain;
}

static void write_environ(int fd, char* key, char* value) 
{
	char buf[256];
	sprintf(buf, "%s", key);
	sprintf(buf + strlen(buf), "%s", "=");
	sprintf(buf + strlen(buf), "%s\n", value);
	write(fd, buf, strlen(buf)); 
}

static void make_tmp_environ(struct opts *opts, int pfd)
{
	char buf[4096];
	char *old_preload, *old_libpath;
	bool must_use_multi_thread = check_libpthread(opts->exename);
	int env_fd;
	char name[] = "/tmp/uftrace_environ_file";
	
	// env_fd = mkstemp(name);
	env_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	if (opts->lib_path) {
		strcpy(buf, opts->lib_path);
		strcat(buf, "/libmcount:");
	} else {
		/* to make strcat() work */
		buf[0] = '\0';
	}

#ifdef INSTALL_LIB_PATH
	strcat(buf, INSTALL_LIB_PATH);
#endif

	old_libpath = getenv("LD_LIBRARY_PATH");
	if (old_libpath) {
		size_t len = strlen(buf) + strlen(old_libpath) + 2;
		char *libpath = xmalloc(len);

		snprintf(libpath, len, "%s:%s", buf, old_libpath);
		setenv("LD_LIBRARY_PATH", libpath, 1);
		free(libpath);
	}
	else
		setenv("LD_LIBRARY_PATH", buf, 1);

	if (opts->filter) {
		char *filter_str = uftrace_clear_kernel(opts->filter);

		if (filter_str) {
			write_environ(env_fd, "UFTRACE_FILTER", filter_str);
			//setenv("UFTRACE_FILTER", filter_str, 1);
			free(filter_str);
		}
	}

	if (opts->trigger) {
		char *trigger_str = uftrace_clear_kernel(opts->trigger);

		if (trigger_str) {
			write_environ(env_fd, "UFTRACE_TRIGGER", trigger_str);
			setenv("UFTRACE_TRIGGER", trigger_str, 1);
			free(trigger_str);
		}
	}

	if (opts->retval) {
		char *retval_str = uftrace_clear_kernel(opts->retval);

		if (retval_str) {
			write_environ(env_fd, "UFTRACE_RETVAL", retval_str);
			setenv("UFTRACE_RETVAL", retval_str, 1);
			free(retval_str);
		}
	}

	if (opts->auto_args)
		write_environ(env_fd, "UFTRACE_AUTO_ARGS", "1");
		//setenv("UFTRACE_AUTO_ARGS", "1", 1);

	if (opts->patch) {
		char *patch_str = uftrace_clear_kernel(opts->patch);

		if (patch_str) {
			write_environ(env_fd, "UFTRACE_PATCH", patch_str);
			setenv("UFTRACE_PATCH", patch_str, 1);
			free(patch_str);
		}
	}

	if (opts->event) {
		char *event_str = uftrace_clear_kernel(opts->event);

		if (event_str) {
			write_environ(env_fd, "UFTRACE_EVENT", event_str);
			setenv("UFTRACE_EVENT", event_str, 1);
			free(event_str);
		}
	}

	if (opts->depth != OPT_DEPTH_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		write_environ(env_fd, "UFTRACE_DEPTH", buf);
		setenv("UFTRACE_DEPTH", buf, 1);
	}

	if (opts->max_stack != OPT_RSTACK_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		write_environ(env_fd, "UFTRACE_MAX_STACK", buf);
		setenv("UFTRACE_MAX_STACK", buf, 1);
	}

	if (opts->threshold) {
		snprintf(buf, sizeof(buf), "%"PRIu64, opts->threshold);
		write_environ(env_fd, "UFTRACE_THRESHOLD", buf);
		setenv("UFTRACE_THRESHOLD", buf, 1);
	}

	if (opts->libcall) {
		write_environ(env_fd, "UFTRACE_PLTHOOK", "1");
		setenv("UFTRACE_PLTHOOK", "1", 1);

		if (opts->want_bind_not) {
			/* do not update GOTPLT after resolving symbols */
			write_environ(env_fd, "LD_BIND_NOT", "1");
			setenv("LD_BIND_NOT", "1", 1);
		}

		if (opts->nest_libcall) {
			write_environ(env_fd, "UFTRACE_NEST_LIBCALL", "1");
			setenv("UFTRACE_NEST_LIBCALL", "1", 1);
		}
	}

	if (strcmp(opts->dirname, UFTRACE_DIR_NAME)) {
		write_environ(env_fd, "UFTRACE_DIR", opts->dirname);
		setenv("UFTRACE_DIR", opts->dirname, 1);
	}

	if (opts->bufsize != SHMEM_BUFFER_SIZE) {
		snprintf(buf, sizeof(buf), "%lu", opts->bufsize);
		write_environ(env_fd, "UFTRACE_BUFFER", buf);
		setenv("UFTRACE_BUFFER", buf, 1);
	}

	if (opts->logfile) {
		snprintf(buf, sizeof(buf), "%d", fileno(logfp));
		write_environ(env_fd, "UFTRACE_LOGFD", buf);
		setenv("UFTRACE_LOGFD", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", pfd);
	setenv("UFTRACE_PIPE", buf, 1);
	write_environ(env_fd, "UFTRACE_PIPE", buf);
	setenv("UFTRACE_SHMEM", "1", 1);
	write_environ(env_fd, "UFTRACE_SHMEM", "1");

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		setenv("UFTRACE_DEBUG", buf, 1);
		write_environ(env_fd, "UFTRACE_DEBUG", buf);
		setenv("UFTRACE_DEBUG_DOMAIN", build_debug_domain_string(), 1);
		write_environ(env_fd, "UFTRACE_DEBUG_DOMAIN", build_debug_domain_string());
	}

	if(opts->disabled) {
		setenv("UFTRACE_DISABLED", "1", 1);
		write_environ(env_fd, "UFTRACE_DISABLED", "1");
	}

	if (log_color == COLOR_ON) {
		snprintf(buf, sizeof(buf), "%d", log_color);
		setenv("UFTRACE_COLOR", buf, 1);
		write_environ(env_fd, "UFTRACE_COLOR", buf);
	}

	snprintf(buf, sizeof(buf), "%d", demangler);
	setenv("UFTRACE_DEMANGLE", buf, 1);
	write_environ(env_fd, "UFTRACE_DEMANGLE", buf);

	if ((opts->kernel || has_kernel_event(opts->event)) &&
	    check_kernel_pid_filter()) {
		setenv("UFTRACE_KERNEL_PID_UPDATE", "1", 1);
		write_environ(env_fd, "UFTRACE_KERNEL_PID_UPDATE", "1");
	}

	if (opts->script_file) {
		setenv("UFTRACE_SCRIPT", opts->script_file, 1);
		write_environ(env_fd, "UFTRACE_SCRIPT", opts->script_file);
	}

	if (opts->lib_path)
		snprintf(buf, sizeof(buf), "%s/libmcount/", opts->lib_path);
	else
		buf[0] = '\0';  /* to make strcat() work */
	strcat(buf, "libmcount-dynamic.so");
	pr_dbg("using %s library for tracing\n", buf);

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(buf) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", buf, old_preload);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", buf, 1);
	write_environ(env_fd, "TRACE_LIBRARY", buf);

	// for DYNAMIC
	snprintf(buf, sizeof(buf), "%d", getpid());
	write_environ(env_fd, "UFTRACE_PID", buf);

	// The below code should be placed at the end.	
	setenv("XRAY_OPTIONS", "patch_premain=false", 1);
	write_environ(env_fd, "XRAY_OPTIONS", "patch_premain=false");
}


static int shmem_lost_count;

struct tid_list {
	struct list_head list;
	int pid;
	int tid;
	bool exited;
};

static LIST_HEAD(tid_list_head);

struct dlopen_list {
        struct list_head list;
        char *libname;
};

static LIST_HEAD(dlopen_libs);


void setup_uftrace_environ(struct opts *opts, int pfd)
{
	make_tmp_environ(opts, pfd);
}

int do_inject(int pfd[2], int ready, struct opts *opts, char *argv[])
{
	int target_pid = opts->pid;
        uint64_t dummy;
        close(pfd[0]);
	setup_uftrace_environ(opts, pfd[1]);

        if (read(ready, &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
                pr_err("waiting for parent failed");

	// TODO : do inject libmcount-dynamic.so to specific process
	pr_dbg("ENVIRONMENT READY. NOw INJECTING...\n");	

	// to easier test.
	//execv("./dlopen", &argv[opts->idx]);
	inject("libtrigger.so", target_pid);
        //abort();

}

int find_exefile(struct opts *opts) {
	DIR *directory = opendir("/proc/");
	char* exePath;
	int exePathLen;
	ssize_t len;
	pid_t pid = opts->pid;

	if (!directory) 
		return 0;
	exePath = malloc(exePathLen * sizeof(char));
	sprintf(exePath, "/proc/%d/exe", pid);
	exePath[exePathLen-1] = '\0';
	len = readlink(exePath, absolute_file_path, PATH_MAX - 1);
	if(len == -1)
	{
		free(exePath);
		return 0;
	}
	absolute_file_path[len] = '\0';
	free(exePath);
	closedir(directory);
	opts->exename = absolute_file_path;
	return 1;
}

int dynamic_child_exec(int pfd[2], int ready, struct opts *opts, char *argv[])
{
	uint64_t dummy;

	close(pfd[0]);

	setup_uftrace_environ(opts, pfd[1]);

	/* wait for parent ready */
	if (read(ready, &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
		pr_err("waiting for parent failed");

	/*
	 * I don't think the traced binary is in PATH.
	 * So use plain 'execv' rather than 'execvp'.
	 */
	pr_dbg("ARGV : %s\n", argv[opts->idx]);
	execv(opts->exename, &argv[opts->idx]);
	abort();
}

#define DYNAMIC_TO_PROCESS 0
#define DYNAMIC_TO_PROGRAM 1

int command_dynamic(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int pfd[2];
	int efd;
	int ret = -1;
	int flag = DYNAMIC_TO_PROCESS;

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	if (create_directory(opts->dirname) < 0)
		return -1;

	/* apply script-provided options */
	if (opts->script_file)
		parse_script_opt(opts);


	/************
	* dynamic stub start
	*************/
	if (!opts->pid) {
		pr_dbg("Dynamic Trace to Program\n");
		flag = DYNAMIC_TO_PROGRAM;
	} else {
		pr_dbg("Dynamic Trace to already running Program\n");
		flag = DYNAMIC_TO_PROCESS;

		if (!find_exefile(opts)) 
			pr_err("Cannot find executable file path\n");
	}
	
	pr_dbg("FIND EXECUTABLE FILE PATH : %s\n", opts->exename);
	

	// dynamic stub END

	has_perf_event = check_linux_perf_event(opts->event);

	fflush(stdout);

	efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (efd < 0)
		pr_dbg("creating eventfd failed: %d\n", efd);

	pid = fork();

        if (pid < 0)
                pr_err("cannot start child process");

	if (flag) {
		// Dynamic to program
		if (pid == 0) {
			if (opts->keep_pid)
				ret = do_main_loop(pfd, efd, opts, getppid());
			else
				dynamic_child_exec(pfd, efd, opts, argv);
			return ret;
		}

		if (opts->keep_pid)
			dynamic_child_exec(pfd, efd, opts, argv);
		else
			ret = do_main_loop(pfd, efd, opts, pid);

	} else {
		// Dynamic to process
		if (pid == 0)  
			do_inject(pfd, efd, opts, argv);
		else
			ret = do_main_loop(pfd, efd, opts, pid);

	}
	return ret;
}
