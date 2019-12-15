#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "libmcount/mcount.h"


static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	if (!tmp_dirname)
		return;

	remove_directory(tmp_dirname);
	tmp_dirname = NULL;
}

static void reset_live_opts(struct opts *opts)
{
	/* this is needed to set display_depth at replay */
	live_disabled = opts->disabled;

	/*
	 * These options are handled in record and no need to do it in
	 * replay again.
	 */
	free(opts->filter);
	opts->filter = NULL;
	free(opts->caller);
	opts->caller = NULL;

	opts->depth	= MCOUNT_DEFAULT_DEPTH;
	opts->disabled	= false;
	opts->no_event  = false;
}

static void sigsegv_handler(int sig)
{
	pr_warn("Segmentation fault\n");
	cleanup_tempdir();
	raise(sig);
}

static bool can_skip_replay(struct opts *opts, int record_result)
{
	if (opts->nop)
		return true;

	return false;
}

static void setup_child_environ(struct opts *opts)
{
	char *old_preload, *libpath;

#ifdef INSTALL_LIB_PATH
	if (!opts->lib_path) {
		char *envbuf = getenv("LD_LIBRARY_PATH");

		if (envbuf) {
			envbuf = xstrdup(envbuf);
			libpath = strjoin(envbuf, INSTALL_LIB_PATH, ":");
			setenv("LD_LIBRARY_PATH", libpath, 1);
			free(libpath);
		}
		else {
			setenv("LD_LIBRARY_PATH", INSTALL_LIB_PATH, 1);
		}
	}
#endif

	libpath = get_libmcount_path(opts);
	if (libpath == NULL)
		pr_err_ns("cannot found libmcount.so\n");

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(libpath) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", libpath, old_preload);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", libpath, 1);

	free(libpath);
}

struct symtabs live_symtabs;
struct uftrace_record_stack {
	unsigned int count;
	struct uftrace_record **stack;
};

struct uftrace_record_stack rstack;
struct uftrace_record *lastest_entry;

static void push_rec(struct uftrace_record *rec, struct uftrace_record_stack *stack)
{
	pr_dbg("%s] count: %d %lx\n", __func__, stack->count, rec);
	stack->stack[stack->count++] = rec;
}
static struct uftrace_record *pop_rec(struct uftrace_record_stack *stack)
{
	pr_dbg("%s] count: %d : %lx\n", __func__, stack->count, stack->stack[stack->count-1]);

	if (stack->count)
		return stack->stack[--stack->count];

	return NULL;
}

static struct uftrace_record *top_rec(struct uftrace_record_stack *stack)
{
	if (stack->count)
		return stack->stack[stack->count-1];

	return NULL;
}

struct uftrace_record_reader {
	void *data;
	void *pos;
	unsigned int len;
};

struct uftrace_record *next_rec(struct uftrace_record_reader *reader)
{
	if (reader->pos + sizeof(struct uftrace_record)
			<= reader->data + reader->len) {
		struct uftrace_record *rec;
		rec = reader->pos + sizeof(struct uftrace_record);
		return rec;
	}

	return NULL;
}

struct uftrace_record *read_rec(struct uftrace_record_reader *reader)
{
	if (reader->pos <= reader->data + reader->len) {
		struct uftrace_record *rec;
		rec = (struct uftrace_record *)reader->pos;
		return rec;
	}

	return NULL;
}

struct uftrace_record *read_rec_inc(struct uftrace_record_reader *reader)
{
	if (reader->pos <= reader->data + reader->len) {
		struct uftrace_record *rec;
		rec = (struct uftrace_record *)reader->pos;
		reader->pos += sizeof(struct uftrace_record);
		return rec;
	}

	return NULL;
}

void live_init_symtabs()
{
}

void live_handle_dlopen(char *exename)
{
	load_module_symtab(&live_symtabs, exename);
}

static struct uftrace_record *next_record(struct uftrace_record *curr)
{
}

static void handle_uftrace_entry(int tid, struct uftrace_record *curr,
		struct uftrace_record_reader *reader,
		struct uftrace_record_stack *stack)
{
	struct uftrace_record *prev = top_rec(stack);
	struct uftrace_record *next = read_rec(reader);

	if (prev && prev->type == UFTRACE_ENTRY)
		pr_out(" { \n");

	if (next && next->type == UFTRACE_EXIT)
		pr_dbg("CURRENT : %lx, NEXT : %lx", curr->addr, next->addr);
	else
		pr_out(" %10s [%6d] | %*s%lx()", "", tid, 2 * curr->depth, "", curr->addr);

	pr_dbg("%s CURRENT ADDR : %lx \n", __func__, curr->addr);

	push_rec(curr, stack);
	lastest_entry = curr;
}

static void handle_uftrace_exit(int tid, struct uftrace_record *curr,
		struct uftrace_record_reader *reader,
		struct uftrace_record_stack *stack)
{
	struct uftrace_record *prev = pop_rec(stack);
	uint64_t test = 10928018203821093;

	if (prev && prev->type == UFTRACE_ENTRY && prev == lastest_entry)
		pr_out(" %7.3f %s [%6d] | %*s%lx();\n",
				(float)curr->time - (float)prev->time, "us",
				tid, 2 * curr->depth, "", curr->addr);

	else
		pr_out(" %7.3f %s [%6d] | %*s}\n",
				(float)curr->time - (float)prev->time, "us",
				tid, 2 * curr->depth, "");


	pr_dbg("%s CURRENT ADDR : %lx \n", __func__, curr->addr);

}

static void handle_uftrace_lost(int tid, struct uftrace_record *curr,
		struct uftrace_record_stack *stack)
{
	pr_out(" XXX %d: lost %d records\n",
			tid, (int)curr->addr);
}

static void handle_uftrace_event(int tid, struct uftrace_record *curr,
		struct uftrace_record_stack *stack)
{
	pr_out("!!! %d: ", tid);
	// print_event(task, curr, task->event_color);
	pr_out(" time (%"PRIu64")\n", curr->time);
}

void print_trace_data(int tid, void *data, size_t len)
{
	struct uftrace_record *curr, *prev = NULL;
	static int count;
	uint64_t ptime;

	struct uftrace_record_reader reader;
	reader.data = data;
	reader.pos = data;
	reader.len = len;

	while((curr = read_rec_inc(&reader)) != NULL) {
		switch (curr->type) {
		case UFTRACE_ENTRY:
			handle_uftrace_entry(tid, curr, &reader, &rstack);
			break;

		case UFTRACE_EXIT:
			handle_uftrace_exit(tid, curr, &reader, &rstack);
			break;

		case UFTRACE_LOST:
			handle_uftrace_lost(tid, curr, &rstack);
			break;

		case UFTRACE_EVENT:
			handle_uftrace_event(tid, curr, &rstack);
			break;
		}
		prev = curr;
		curr = (struct uftrace_record *)((uintptr_t)curr + sizeof(*curr));
	}
}

int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/uftrace-live-XXXXXX";
	int fd;
	struct sigaction sa = {
		.sa_flags = SA_RESETHAND,
	};
	int ret;

	live_symtabs.dirname = opts->dirname;
	live_symtabs.flags = SYMTAB_FL_ADJ_OFFSET;
	rstack.stack = xmalloc(opts->max_stack * sizeof(struct uftrace_record *));

	if (!opts->record) {
		tmp_dirname = template;
		umask(022);
		fd = mkstemp(template);
		if (fd < 0) {
			if (errno != EPERM)
				pr_err("cannot access to /tmp");

			fd = mkstemp(template + sizeof("/tmp/") - 1);

			if (fd < 0)
				pr_err("cannot create temp name");
			tmp_dirname += sizeof("/tmp/") - 1;
		}

		close(fd);
		unlink(tmp_dirname);

		atexit(cleanup_tempdir);

		sa.sa_handler = sigsegv_handler;
		sigfillset(&sa.sa_mask);
		sigaction(SIGSEGV, &sa, NULL);

		opts->dirname = tmp_dirname;
	}

	if (opts->list_event) {
		if (geteuid() == 0)
			list_kernel_events();

		if (fork() == 0) {
			setup_child_environ(opts);
			setenv("UFTRACE_LIST_EVENT", "1", 1);

			execv(opts->exename, argv);
			abort();
		}
		return 0;
	}

	ret = command_record(argc, argv, opts);
	/*
	if (!can_skip_replay(opts, ret)) {
		int ret2;

		reset_live_opts(opts);

		if (opts->use_pager)
			start_pager(setup_pager());

		pr_dbg("live-record finished.. \n");
		if (opts->report) {
			pr_out("#\n# uftrace report\n#\n");
			ret2 = command_report(argc, argv, opts);
			if (ret == UFTRACE_EXIT_SUCCESS)
				ret = ret2;

			pr_out("\n#\n# uftrace replay\n#\n");
		}

		pr_dbg("start live-replaying...\n");
		ret2 = command_replay(argc, argv, opts);
		if (ret == UFTRACE_EXIT_SUCCESS)
			ret = ret2;
	}
	*/

	cleanup_tempdir();

	return ret;
}
