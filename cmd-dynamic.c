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
#include "cmd-record.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/filter.h"
#include "utils/kernel.h"
#include "utils/perf.h"
#include "utils/debugger.h"

#define SHMEM_NAME_SIZE (64 - (int)sizeof(struct list_head))

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

	printf("LOG setup environ\n");
	snprintf(buf, sizeof(buf), "%d", getpid());
	write_environ(env_fd, "UFTRACE_PID", buf);
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
	write_environ(env_fd, "TRACE_LIBRARY", buf);

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

static void read_record_mmap(int pfd, const char *dirname, int bufsize)
{
	char buf[128];
	struct shmem_list *sl, *tmp;
	struct tid_list *tl, *pos;
	struct uftrace_msg msg;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess sess;
	struct uftrace_msg_dlopen dmsg;
	struct dlopen_list *dlib;
	char *exename;
	int lost;

	if (read_all(pfd, &msg, sizeof(msg)) < 0)
		pr_err("reading pipe failed:");

	if (msg.magic != UFTRACE_MSG_MAGIC)
		pr_err_ns("invalid message received: %x\n", msg.magic);

	switch (msg.type) {
	case UFTRACE_MSG_REC_START:
		pr_dbg("MSG_REC_START\n");
		if (msg.len >= SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		sl = xmalloc(sizeof(*sl));

		if (read_all(pfd, sl->id, msg.len) < 0)
			pr_err("reading pipe failed");

		sl->id[msg.len] = '\0';
		pr_dbg2("MSG START: %s\n", sl->id);

		/* link to shmem_list */
		list_add_tail(&sl->list, &shmem_list_head);
		break;

	case UFTRACE_MSG_REC_END:
		pr_dbg("UFTRACE_MSG_REC_END\n");
		if (msg.len >= SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, buf, msg.len) < 0)
			pr_err("reading pipe failed");

		buf[msg.len] = '\0';
		pr_dbg2("MSG  END : %s\n", buf);

		/* remove from shmem_list */
		list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
			if (!memcmp(sl->id, buf, SHMEM_NAME_SIZE)) {
				list_del(&sl->list);
				free(sl);
				break;
			}
		}

		record_mmap_file(dirname, buf, bufsize);
		break;

	case UFTRACE_MSG_TASK_START:
		pr_dbg("UFTRACE_MSG_TASK_START\n");
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG TASK_START : %d/%d\n", tmsg.pid, tmsg.tid);

		/* check existing tid (due to exec) */
		list_for_each_entry(pos, &tid_list_head, list) {
			if (pos->tid == tmsg.tid) {
				flush_old_shmem(dirname, tmsg.tid, bufsize);
				break;
			}
		}

		if (list_no_entry(pos, &tid_list_head, list))
			add_tid_list(tmsg.pid, tmsg.tid);

		write_task_info(dirname, &tmsg);
		break;

	case UFTRACE_MSG_TASK_END:
		pr_dbg("UFTRACE_MSG_TASK_END\n");
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG TASK_END : %d/%d\n", tmsg.pid, tmsg.tid);

		/* mark test exited */
		list_for_each_entry(pos, &tid_list_head, list) {
			if (pos->tid == tmsg.tid) {
				pos->exited = true;
				break;
			}
		}
		break;

	case UFTRACE_MSG_FORK_START:
		pr_dbg("FORK\n");
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG FORK1: %d/%d\n", tmsg.pid, -1);

		add_tid_list(tmsg.pid, -1);
		break;

	case UFTRACE_MSG_FORK_END:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		list_for_each_entry(tl, &tid_list_head, list) {
			if (tl->pid == tmsg.pid && tl->tid == -1)
				break;
		}

		if (list_no_entry(tl, &tid_list_head, list)) {
			/*
			 * daemon process has no guarantee that having parent
			 * pid of 1 anymore due to the systemd, just pick a
			 * first task which has tid of -1.
			 */
			list_for_each_entry(tl, &tid_list_head, list) {
				if (tl->tid == -1) {
					pr_dbg3("override parent of daemon to %d\n",
						tl->pid);
					tmsg.pid = tl->pid;
					break;
				}
			}
		}

		if (list_no_entry(tl, &tid_list_head, list))
			pr_err("cannot find fork pid: %d\n", tmsg.pid);

		tl->tid = tmsg.tid;

		pr_dbg2("MSG FORK2: %d/%d\n", tl->pid, tl->tid);

		write_fork_info(dirname, &tmsg);
		break;

	case UFTRACE_MSG_SESSION:
		pr_dbg("SESSION\n");
		if (msg.len < sizeof(sess))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &sess, sizeof(sess)) < 0)
			pr_err("reading pipe failed");

		exename = xmalloc(sess.namelen + 1);
		if (read_all(pfd, exename, sess.namelen) < 0)
			pr_err("reading pipe failed");
		exename[sess.namelen] = '\0';

		memcpy(buf, sess.sid, 16);
		buf[16] = '\0';

		pr_dbg2("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);

		write_session_info(dirname, &sess, exename);
		free(exename);
		break;

	case UFTRACE_MSG_LOST:
		if (msg.len < sizeof(lost))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &lost, sizeof(lost)) < 0)
			pr_err("reading pipe failed");

		shmem_lost_count += lost;
		break;

	case UFTRACE_MSG_DLOPEN:
		if (msg.len < sizeof(dmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &dmsg, sizeof(dmsg)) < 0)
			pr_err("reading pipe failed");

		exename = xmalloc(dmsg.namelen + 1);
		if (read_all(pfd, exename, dmsg.namelen) < 0)
			pr_err("reading pipe failed");
		exename[dmsg.namelen] = '\0';

		pr_dbg2("MSG DLOPEN: %d: %#lx %s\n", dmsg.task.tid, dmsg.base_addr, exename);

		dlib = xmalloc(sizeof(*dlib));
		dlib->libname = exename;
		list_add_tail(&dlib->list, &dlopen_libs);

		write_dlopen_info(dirname, &dmsg, exename);
		/* exename will be freed with the dlib */
		break;

	case UFTRACE_MSG_FINISH:
		pr_dbg2("MSG FINISH\n");
		break;

	default:
		pr_warn("Unknown message type: %u\n", msg.type);
		break;
	}
}

void setup_uftrace_environ(struct opts *opts, int pfd)
{
	printf("setup start\n");
	make_tmp_environ(opts, pfd);
	printf("setup end\n");
}



struct symtabs symtabs = {
        .flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET,
};

void test_bp(struct opts *opts);

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

	//test_bp(opts);
}

void test_bp(struct opts *opts)
{
	pr_dbg("TEST BP\n");
	int target_pid = opts->pid;
	symtabs.dirname = opts->dirname;
	load_symtabs(&symtabs, NULL, opts->exename);

        struct timeval val;
        gettimeofday(&val, NULL);
        printf("%ld:%ld\n", val.tv_sec, val.tv_usec);

	struct symtab uftrace_symtab = symtabs.symtab;
	// attach to target. pray all child thread have to work correctly.
	debugger_init(target_pid);
	int base_addr = 0x400000;
	for(int index=0;index < uftrace_symtab.nr_sym;index++) {
		struct sym _sym = uftrace_symtab.sym[index];
		printf("[%d] %lx  %d :  %s\n", index, base_addr + _sym.addr, _sym.size, _sym.name);
		
		// at least, code size must larger than size of int. 
		if (_sym.size > sizeof(4)) {
			// set break point and save origin instruction. 
			set_break_point(base_addr + _sym.addr);
		}
		
	}

        gettimeofday(&val, NULL);
        printf("%ld:%ld\n", val.tv_sec, val.tv_usec);

	print_hashmap();
	pr_dbg("Continue");
	// continue 
	if(ptrace(PTRACE_CONT, target_pid, NULL, NULL)) {
		pr_dbg("PTRACE CONTINUE FAILED");
		exit(1);
	}
	// set a listener by using waitpid.`
	int status;
	waitpid(target_pid, &status, 0);
	pr_dbg("SIGNAL %x", WTERMSIG(status));
	if (WIFEXITED(status)) {
		printf("PROCESS EXITED\n");
	}
	else if (WIFSIGNALED(status)) {
		printf("SIGNAL %x\n", WTERMSIG(status));

	}
	else if (WIFSTOPPED(status)) {
		printf("STOP %x\n", WTERMSIG(status));
		// when reach here by SIGTRAP, we record it 
		// by calling __fentry__.
		gettimeofday(&val, NULL);
		printf("%ld:%ld\n", val.tv_sec, val.tv_usec);
		remove_break_point();
		gettimeofday(&val, NULL);
		printf("%ld:%ld\n", val.tv_sec, val.tv_usec);

		// __fentry__();	
		// restore origin and execute that.
		
		// set the break-point again. after that continue.
	}
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

int command_dynamic(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int pfd[2];
	int efd;
	int ret = -1;

	if (!find_exefile(opts)) 
		pr_err("Cannot find executable file path\n");

	pr_dbg("FIND EXECUTABLE FILE PATH : %s\n", opts->exename);
	if (opts->pid <= 0) 
		pr_err("process id is invalid\n");

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	if (create_directory(opts->dirname) < 0)
		return -1;

	/* apply script-provided options */
	if (opts->script_file)
		parse_script_opt(opts);

	has_perf_event = check_linux_perf_event(opts->event);

	fflush(stdout);

	efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (efd < 0)
		pr_dbg("creating eventfd failed: %d\n", efd);

	pid = fork();

        if (pid < 0)
                pr_err("cannot start child process");

        if (pid == 0) 
		do_inject(pfd, efd, opts, argv);
        else
                ret = do_main_loop(pfd, efd, opts, pid);
        return ret;
}
