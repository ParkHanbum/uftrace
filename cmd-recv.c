#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/wait.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/list.h"


#define SHMEM_NAME_SIZE (64 - (int)sizeof(struct list_head))

static void read_record_mmap(int pfd, int efd, const char *dirname, struct opts* opts);

struct client_data {
	struct list_head	list;
	int			sock;
	char			*dirname;
};

static LIST_HEAD(client_list);

static int server_socket(struct opts *opts)
{
	int sock;
	int on = 1;
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_addr	= {
			.s_addr	= htonl(INADDR_ANY),
		},
		.sin_port	= htons(opts->port),
	};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		pr_err("socket creation failed");

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		pr_err("socket bind failed");

	if (listen(sock, 5) < 0)
		pr_err("socket listen failed");

	return sock;
}

static int signal_fd(struct opts *opts)
{
	int fd;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
		pr_err("signal block failed");

	fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (fd < 0)
		pr_err("signalfd failed");

	return fd;
}

/* client (record) side API */
int setup_client_socket(struct opts *opts)
{
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= htons(opts->port),
	};
	struct hostent *hostinfo;
	int sock;
	int one = 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		pr_err("socket create failed");

	setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one));

	hostinfo = gethostbyname(opts->host);
	if (hostinfo == NULL)
		pr_err("cannot find host: %s", opts->host);

	addr.sin_addr = *(struct in_addr *) hostinfo->h_addr;

	if (connect(sock, &addr, sizeof(addr)) < 0)
		pr_err("socket connect failed");

	return sock;
}

void send_trace_dir_name(int sock, char *name)
{
	ssize_t len = strlen(name);
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_DIR_NAME),
		.len   = htonl(len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = name, .iov_len = len, },
	};

	pr_dbg2("send UFTRACE_MSG_SEND_HDR\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send header failed");
}

void send_trace_data(int sock, int tid, void *data, size_t len)
{
	int32_t msg_tid = htonl(tid);
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_DATA),
		.len   = htonl(sizeof(msg_tid) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &msg_tid, .iov_len = sizeof(msg_tid), },
		{ .iov_base = data,     .iov_len = len, },
	};

	printf("%x \n", msg.magic);

	pr_dbg2("send UFTRACE_MSG_SEND_DATA\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send data failed");
}

void send_trace_kernel_data(int sock, int cpu, void *data, size_t len)
{
	int32_t msg_cpu = htonl(cpu);
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_KERNEL_DATA),
		.len   = htonl(sizeof(msg_cpu) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &msg_cpu, .iov_len = sizeof(msg_cpu), },
		{ .iov_base = data,     .iov_len = len, },
	};

	pr_dbg2("send UFTRACE_MSG_SEND_KERNEL_DATA\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send kernel data failed");
}

void send_trace_perf_data(int sock, int cpu, void *data, size_t len)
{
	int32_t msg_cpu = htonl(cpu);
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_PERF_DATA),
		.len   = htonl(sizeof(msg_cpu) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &msg_cpu, .iov_len = sizeof(msg_cpu), },
		{ .iov_base = data,     .iov_len = len, },
	};

	pr_dbg2("send UFTRACE_MSG_SEND_PERF_DATA\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send kernel data failed");
}

void send_trace_metadata(int sock, const char *dirname, char *filename)
{
	int fd;
	void *buf;
	size_t len;
	char *pathname = NULL;
	struct stat stbuf;
	int32_t namelen = strlen(filename);
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_META_DATA),
		.len   = sizeof(namelen) + namelen,
	};
	struct iovec iov[4] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &namelen, .iov_len = sizeof(namelen), },
		{ .iov_base = filename, .iov_len = namelen, },
		{ /* to be filled */ },
	};

	xasprintf(&pathname, "%s/%s", dirname, filename);

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		pr_err("open %s failed", pathname);

	if (fstat(fd, &stbuf) < 0)
		pr_err("stat %s failed", pathname);

	len = stbuf.st_size;
	buf = xmalloc(len);

	msg.len = htonl(msg.len + len);
	iov[3].iov_base = buf;
	iov[3].iov_len  = len;

	if (read_all(fd, buf, len) < 0)
		pr_err("map read failed");

	namelen = htonl(namelen);

	pr_dbg2("send UFTRACE_MSG_SEND_META_DATA: %s\n", filename);
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send metadata failed");

	free(pathname);
	free(buf);
	close(fd);
}

void send_trace_info(int sock, struct uftrace_file_header *hdr,
		     void *info, int len)
{
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_INFO),
		.len   = htonl(sizeof(*hdr) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = hdr,      .iov_len = sizeof(*hdr), },
		{ .iov_base = info,     .iov_len = len, },
	};

	hdr->version     = htonl(hdr->version);
	hdr->header_size = htons(hdr->header_size);
	hdr->feat_mask   = htonq(hdr->feat_mask);
	hdr->info_mask   = htonq(hdr->info_mask);
	hdr->max_stack   = htons(hdr->max_stack);

	pr_dbg2("send UFTRACE_MSG_SEND_INFO\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send metadata failed");
}

void send_trace_end(int sock)
{
	struct uftrace_msg msg = {
		.magic = htons(UFTRACE_MSG_MAGIC),
		.type  = htons(UFTRACE_MSG_SEND_END),
	};

	pr_dbg2("send UFTRACE_MSG_SEND_END\n");
	if (write_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("send end failed");
}


/* server (recv) side API */
static struct client_data *find_client(int sock)
{
	struct client_data *c;

	list_for_each_entry(c, &client_list, list) {
		if (c->sock == sock)
			return c;
	}
	return NULL;
}

#define O_CLIENT_FLAGS  (O_WRONLY | O_APPEND | O_CREAT)

static void write_client_file(struct client_data *c, char *filename, int nr, ...)
{
	int i, fd;
	va_list ap;
	struct iovec iov[nr];
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%s", c->dirname, filename);
	fd = open(buf, O_CLIENT_FLAGS, 0644);
	if (fd < 0)
		pr_err("file open failed: %s", buf);

	va_start(ap, nr);
	for (i = 0; i < nr; i++) {
		iov[i].iov_base = va_arg(ap, void *);
		iov[i].iov_len  = va_arg(ap, int);
	}
	va_end(ap);

	if (writev_all(fd, iov, nr) < 0)
		pr_err("write client data failed on %s", buf);

	close(fd);
}

static void recv_trace_dir_name(int sock, int len)
{
	char dirname[len + 1];
	struct client_data *client;

	if (read_all(sock, dirname, len) < 0)
		pr_err("recv header failed");
	dirname[len] = '\0';

	client = xmalloc(sizeof(*client));

	client->sock = sock;
	client->dirname = xstrdup(dirname);
	INIT_LIST_HEAD(&client->list);

	create_directory(dirname);
	pr_dbg3("create directory: %s\n", dirname);

	list_add(&client->list, &client_list);
}

static void recv_trace_data(int sock, int len)
{
	struct client_data *client;
	int32_t tid;
	char *filename = NULL;
	void *buffer;

	client = find_client(sock);
	if (client == NULL)
		pr_err_ns("no client on this socket\n");

	if (read_all(sock, &tid, sizeof(tid)) < 0)
		pr_err("recv tid failed");
	tid = ntohl(tid);

	xasprintf(&filename, "%d.dat", tid);

	len -= sizeof(tid);
	buffer = xmalloc(len);

	if (read_all(sock, buffer, len) < 0)
		pr_err("recv buffer failed");

	write_client_file(client, filename, 1, buffer, len);

	free(buffer);
	free(filename);
}

static void recv_trace_kernel_data(int sock, int len)
{
	struct client_data *client;
	int32_t cpu;
	char *filename = NULL;
	void *buffer;

	client = find_client(sock);
	if (client == NULL)
		pr_err_ns("no client on this socket\n");

	if (read_all(sock, &cpu, sizeof(cpu)) < 0)
		pr_err("recv cpu failed");
	cpu = ntohl(cpu);

	xasprintf(&filename, "kernel-cpu%d.dat", cpu);

	len -= sizeof(cpu);
	buffer = xmalloc(len);

	if (read_all(sock, buffer, len) < 0)
		pr_err("recv buffer failed");

	write_client_file(client, filename, 1, buffer, len);

	free(buffer);
	free(filename);
}

static void recv_trace_perf_data(int sock, int len)
{
	struct client_data *client;
	int32_t cpu;
	char *filename = NULL;
	void *buffer;

	client = find_client(sock);
	if (client == NULL)
		pr_err_ns("no client on this socket\n");

	if (read_all(sock, &cpu, sizeof(cpu)) < 0)
		pr_err("recv cpu failed");
	cpu = ntohl(cpu);

	xasprintf(&filename, "perf-cpu%d.dat", cpu);

	len -= sizeof(cpu);
	buffer = xmalloc(len);

	if (read_all(sock, buffer, len) < 0)
		pr_err("recv buffer failed");

	write_client_file(client, filename, 1, buffer, len);

	free(buffer);
	free(filename);
}

static void recv_trace_metadata(int sock, int len)
{
	struct client_data *client;
	int32_t namelen;
	char *filename = NULL;
	void *filedata;

	client = find_client(sock);
	if (client == NULL)
		pr_err_ns("no client on this socket\n");

	if (read_all(sock, &namelen, sizeof(namelen)) < 0)
		pr_err("recv symfile name length failed");

	namelen = ntohl(namelen);
	filename = xmalloc(namelen + 1);

	if (read_all(sock, filename, namelen) < 0)
		pr_err("recv file name failed");
	filename[namelen] = '\0';

	len -= sizeof(namelen) + namelen;
	filedata = xmalloc(len);

	pr_dbg2("reading %s (%d bytes)\n", filename, len);
	if (read_all(sock, filedata, len) < 0)
		pr_err("recv symfile failed");

	write_client_file(client, filename, 1, filedata, len);

	free(filedata);
	free(filename);
}

static void recv_trace_info(int sock, int len)
{
	struct client_data *client;
	struct uftrace_file_header hdr;
	void *info;

	client = find_client(sock);
	if (client == NULL)
		pr_err_ns("no client on this socket\n");

	if (read_all(sock, &hdr, sizeof(hdr)) < 0)
		pr_err("recv file header failed");

	hdr.version     = ntohl(hdr.version);
	hdr.header_size = ntohs(hdr.header_size);
	hdr.feat_mask   = ntohq(hdr.feat_mask);
	hdr.info_mask   = ntohq(hdr.info_mask);
	hdr.max_stack   = ntohs(hdr.max_stack);

	len -= sizeof(hdr);
	info = xmalloc(len);

	if (read_all(sock, info, len) < 0)
		pr_err("recv info failed");

	write_client_file(client, "info", 2, &hdr, sizeof(hdr), info, len);

	free(info);
}

static void recv_trace_end(int sock, int efd)
{
	struct client_data *client;

	client = find_client(sock);
	if (client) {
		list_del(&client->list);

		pr_dbg("wrote client data to %s\n", client->dirname);

		free(client->dirname);
		free(client);
	}

	if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) < 0)
		pr_err("epoll del failed");

	close(sock);
}

static void execute_run_cmd(char **argv) {
	if (!argv)
		return;

	int pid = fork();
	if (pid < 0)
		pr_err("cannot start child process");

	if (pid == 0) {
		execvp(argv[0], argv);
		pr_err("Failed to execute '%s'", argv[0]);
	}
}

static void epoll_add(int efd, int fd, unsigned event)
{
	struct epoll_event ev = {
		.events	= event,
		.data	= {
			.fd = fd,
		},
	};

	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0)
		pr_err("epoll add failed");
}

static void handle_server_sock(struct epoll_event *ev, int efd)
{
	int client;
	int sock = ev->data.fd;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	char hbuf[NI_MAXHOST];

	client = accept(sock, &addr, &len);
	if (client < 0)
		pr_err("socket accept failed");

	getnameinfo((struct sockaddr *)&addr, len, hbuf, sizeof(hbuf),
		    NULL, 0, NI_NUMERICHOST);

	epoll_add(efd, client, EPOLLIN);
	pr_dbg("new connection added from %s\n", hbuf);
}

static void handle_client_sock(struct epoll_event *ev, int efd, struct opts *opts)
{
	int sock = ev->data.fd;
	struct uftrace_msg msg;
	char buf[128];
        struct shmem_list *sl, *tmp;
        struct tid_list *tl, *pos;
        struct uftrace_msg_task tmsg;
        struct uftrace_msg_sess sess;
        struct uftrace_msg_dlopen dmsg;
        struct dlopen_list *dlib;
        char *exename;
        int lost;
	char *dirname = "uftrace.data";

	if (ev->events & (EPOLLERR | EPOLLHUP)) {
		pr_dbg("client socket closed\n");
		recv_trace_end(sock, efd);
		return;
	}

	read_record_mmap(sock, efd, dirname, opts);
	return;
 
	if (read_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("message recv failed");

	msg.magic = ntohs(msg.magic);
	msg.type  = ntohs(msg.type);
	msg.len   = ntohl(msg.len);


	printf("%x\n", msg.magic);
	if (msg.magic != UFTRACE_MSG_MAGIC) {
		pr_err_ns("invalid message\n");
	}

	switch (msg.type) {
	case UFTRACE_MSG_SEND_DIR_NAME:
		pr_dbg2("receive UFTRACE_MSG_SEND_DIR_NAME\n");
		recv_trace_dir_name(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_DATA\n");
		recv_trace_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_KERNEL_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_KERNEL_DATA\n");
		recv_trace_kernel_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_PERF_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_PERF_DATA\n");
		recv_trace_perf_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_INFO:
		pr_dbg2("receive UFTRACE_MSG_SEND_INFO\n");
		recv_trace_info(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_META_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_META_DATA\n");
		recv_trace_metadata(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_END:
		pr_dbg2("receive UFTRACE_MSG_SEND_END\n");
		recv_trace_end(sock, efd);
		execute_run_cmd(opts->run_cmd);
		break;
	case UFTRACE_MSG_SESSION:
		pr_dbg2("receive UFTRACE_MSG_SESSION\n");
                if (msg.len < sizeof(sess))
                        pr_err_ns("invalid message length\n");

                if (read_all(sock, &sess, sizeof(sess)) < 0)
                        pr_err("reading pipe failed");

                exename = xmalloc(sess.namelen + 1);
                if (read_all(sock, exename, sess.namelen) < 0)
                        pr_err("reading pipe failed");
                exename[sess.namelen] = '\0';

                memcpy(buf, sess.sid, 16);
                buf[16] = '\0';

                pr_dbg2("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);

                write_session_info(dirname, &sess, exename);
                free(exename);
                break;
	default:
		pr_dbg("unknown message: %d\n", msg.type);
		break;
	}
}

int command_recv(int argc, char *argv[], struct opts *opts)
{
	struct signalfd_siginfo si;
	int sock;
	int sigfd;
	int efd;

	if (strcmp(opts->dirname, UFTRACE_DIR_NAME)) {
		char *dirname = "current";

		if ((mkdir(opts->dirname, 0755) == 0 || errno == EEXIST) &&
		    chdir(opts->dirname) == 0)
			dirname = opts->dirname;

		pr_dbg("saving to %s directory\n", dirname);
	}

	sock = server_socket(opts);
	sigfd = signal_fd(opts);

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0)
		pr_err("epoll create failed");

	epoll_add(efd, sock,  EPOLLIN);
	epoll_add(efd, sigfd, EPOLLIN);

	while (!uftrace_done) {
		struct epoll_event ev[10];
		int i, len;

		len = epoll_wait(efd, ev, 10, -1);
		if (len < 0)
			pr_err("epoll wait failed");

		for (i = 0; i < len; i++) {
			if (ev[i].data.fd == sigfd) {
				int nr = read(sigfd, &si, sizeof si);
				if (nr > 0 && si.ssi_signo == SIGCHLD)
					waitpid(-1, NULL, WNOHANG);
				else
					uftrace_done = true;
			}
			else if (ev[i].data.fd == sock)
				handle_server_sock(&ev[i], efd);
			else
				handle_client_sock(&ev[i], efd, opts);
		}
	}

	close(efd);
	close(sigfd);
	close(sock);
	return 0;
}

struct dlopen_list {
	struct list_head list;
	char *libname;
};
struct shmem_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
};
struct tid_list {
        struct list_head list;
        int pid;
        int tid;
        bool exited;
};
static int shmem_lost_count;
static LIST_HEAD(tid_list_head);
static LIST_HEAD(shmem_list_head);
static LIST_HEAD(shmem_need_unlink);
static LIST_HEAD(dlopen_libs);

static void add_tid_list(int pid, int tid)
{
	struct tid_list *tl;

	tl = xmalloc(sizeof(*tl));

	tl->pid = pid;
	tl->tid = tid;
	tl->exited = false;

	/* link to tid_list */
	list_add(&tl->list, &tid_list_head);
}


static void read_record_mmap(int pfd, int efd, const char *dirname, struct opts* opts)
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

	int sock = pfd;
        if (read_all(pfd, &msg, sizeof(msg)) < 0)
                pr_err("reading pipe failed:");
	
	msg.magic = ntohs(msg.magic);
	msg.type  = ntohs(msg.type);
	msg.len   = ntohl(msg.len);

        if (msg.magic != UFTRACE_MSG_MAGIC)
                pr_err_ns("invalid message received: %x\n", msg.magic);

        switch (msg.type) {
        case UFTRACE_MSG_REC_START:
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

                break;

        case UFTRACE_MSG_TASK_START:
                if (msg.len != sizeof(tmsg))
                        pr_err_ns("invalid message length\n");

                if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
                        pr_err("reading pipe failed");

                pr_dbg2("MSG TASK_START : %d/%d\n", tmsg.pid, tmsg.tid);

                /* check existing tid (due to exec) */
                list_for_each_entry(pos, &tid_list_head, list) {
                        if (pos->tid == tmsg.tid) {
                                break;
                        }
                }

                if (list_no_entry(pos, &tid_list_head, list))
                        add_tid_list(tmsg.pid, tmsg.tid);

		write_task_info(dirname, &tmsg);
                break;

        case UFTRACE_MSG_TASK_END:
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
                                        pr_dbg3("override parent of daemon to %d\n"
,
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

                pr_dbg2("MSG DLOPEN: %d: %#lx %s\n", dmsg.task.tid, dmsg.base_addr,
 exename);

                dlib = xmalloc(sizeof(*dlib));
                dlib->libname = exename;
                list_add_tail(&dlib->list, &dlopen_libs);

                write_dlopen_info(dirname, &dmsg, exename);
                /* exename will be freed with the dlib */
                break;

        case UFTRACE_MSG_FINISH:
                pr_dbg2("MSG FINISH\n");
                break;

	case UFTRACE_MSG_SEND_DIR_NAME:
		pr_dbg2("receive UFTRACE_MSG_SEND_DIR_NAME\n");
		recv_trace_dir_name(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_DATA\n");
		recv_trace_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_KERNEL_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_KERNEL_DATA\n");
		recv_trace_kernel_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_PERF_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_PERF_DATA\n");
		recv_trace_perf_data(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_INFO:
		pr_dbg2("receive UFTRACE_MSG_SEND_INFO\n");
		recv_trace_info(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_META_DATA:
		pr_dbg2("receive UFTRACE_MSG_SEND_META_DATA\n");
		recv_trace_metadata(sock, msg.len);
		break;
	case UFTRACE_MSG_SEND_END:
		pr_dbg2("receive UFTRACE_MSG_SEND_END\n");
		recv_trace_end(sock, efd);
		execute_run_cmd(opts->run_cmd);
		break;
	case UFTRACE_MSG_SESSION:
		pr_dbg2("receive UFTRACE_MSG_SESSION\n");
                if (msg.len < sizeof(sess))
                        pr_err_ns("invalid message length\n");

                if (read_all(sock, &sess, sizeof(sess)) < 0)
                        pr_err("reading pipe failed");

                exename = xmalloc(sess.namelen + 1);
                if (read_all(sock, exename, sess.namelen) < 0)
                        pr_err("reading pipe failed");
                exename[sess.namelen] = '\0';

                memcpy(buf, sess.sid, 16);
                buf[16] = '\0';

                pr_dbg2("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);

                write_session_info(dirname, &sess, exename);
                free(exename);
                break;
        default:
                pr_warn("Unknown message type: %u\n", msg.type);
                break;
        }
}
