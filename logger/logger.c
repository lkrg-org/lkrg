/*
 * Standalone TCP server: accepts connections, checks the anti-flood limits,
 * logs and starts the actual sessions.
 *
 * Initially written for popa3d, reused for LKRG logger with minor changes
 * Copyright (c) 1999-2024 Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "misc.h"
#include "params.h"
#include "session.h"

typedef volatile sig_atomic_t va_int;

/*
 * Active sessions.  Those that were started within the last MIN_DELAY
 * seconds are also considered active (regardless of their actual state),
 * to allow for limiting the logging rate without throwing away critical
 * information about sessions that we could have allowed to proceed.
 */
static struct {
	struct in_addr addr;		/* Source IP address */
	volatile int pid;		/* PID of the server, or 0 for none */
	clock_t start;			/* When the server was started */
	clock_t log;			/* When we've last logged a failure */
} sessions[MAX_SESSIONS];

static va_int child_blocked;		/* We use blocking to avoid races */
static va_int child_pending;		/* Are any dead children waiting? */

/*
 * SIGCHLD handler.
 */
static void handle_child(int signum)
{
	int saved_errno;
	int pid;
	int i;

	(void)signum;

	saved_errno = errno;

	if (child_blocked) {
		child_pending = 1;
	} else {
		child_pending = 0;

		while ((pid = waitpid(0, NULL, WNOHANG)) > 0)
		for (i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].pid == pid) {
			sessions[i].pid = 0;
			break;
		}
	}

	signal(SIGCHLD, handle_child);

	errno = saved_errno;
}

static int drop_root(void)
{
	struct passwd *pw;

	errno = 0;
	if (!(pw = getpwnam(DAEMON_USER))) {
		syslog(SYSLOG_PRI_ERROR, "getpwnam(\"" DAEMON_USER "\"): %s",
			errno ? strerror(errno) : "No such user");
		return 1;
	}
	memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));
	endpwent();

	if (!pw->pw_uid) {
		syslog(SYSLOG_PRI_ERROR, "getpwnam(\"" DAEMON_USER "\"): Invalid user");
		return 1;
	}

	if (setgroups(1, &pw->pw_gid))
		return log_error("setgroups");
	if (setgid(pw->pw_gid))
		return log_error("setgid");
	if (setuid(pw->pw_uid))
		return log_error("setuid");

	return 0;
}

int main(int argc, const char * const *argv)
{
	int true = 1;
	int sock, new;
	struct sockaddr_in addr;
	socklen_t addrlen;
	int pid;
	struct tms buf;
	clock_t min_delay, now, log;
	int i, j, n;

/* Must have either no options or -D, which disables daemonization */
	int daemonize = (argc != 2 || strcmp(argv[1], "-D"));
	if (argc != 1 && daemonize) {
		fputs("Usage: lkrg-logger [-D]\n", stderr);
		return 1;
	}

	umask(077);

	openlog(SYSLOG_IDENT, SYSLOG_OPTIONS | LOG_PERROR, SYSLOG_FACILITY);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		return log_error("socket");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    (void *)&true, sizeof(true)))
		return log_error("setsockopt");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(DAEMON_ADDR);
	addr.sin_port = htons(DAEMON_PORT);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		return log_error("bind");

	if (drop_root() || session_prepare())
		return 1;

	if (listen(sock, MAX_BACKLOG))
		return log_error("listen");

	chdir("/");
	setsid();

	if (daemonize) {
		switch (fork()) {
		case -1:
			return log_error("fork");

		case 0:
			break;

		default:
			return 0;
		}

		setsid();
	}

/* Drop LOG_PERROR */
	closelog();
	openlog(SYSLOG_IDENT, SYSLOG_OPTIONS, SYSLOG_FACILITY);

#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	min_delay = MIN_DELAY * sysconf(_SC_CLK_TCK);
#else
	min_delay = MIN_DELAY * CLK_TCK;
#endif

	child_blocked = 1;
	child_pending = 0;
	signal(SIGCHLD, handle_child);

	memset((void *)sessions, 0, sizeof(sessions));
	log = 0;

	new = 0;

	while (1) {
		child_blocked = 0;
		if (child_pending)
			raise(SIGCHLD);

		if (new > 0 && close(new))
			return log_error("close");

		addrlen = sizeof(addr);
		new = accept(sock, (struct sockaddr *)&addr, &addrlen);

/*
 * I wish there were a portable way to classify errno's...  In this case,
 * it appears to be better to risk eating up the CPU on a fatal error
 * rather than risk terminating the entire service because of a minor
 * temporary error having to do with one particular connection attempt.
 */
		if (new < 0)
			continue;

		now = times(&buf);
		if (!now)
			now = 1;

		child_blocked = 1;

		j = -1; n = 0;
		for (i = 0; i < MAX_SESSIONS; i++) {
			if (sessions[i].start > now)
				sessions[i].start = 0;
			if (sessions[i].pid ||
			    (sessions[i].start &&
			    now - sessions[i].start < min_delay)) {
				if (sessions[i].addr.s_addr ==
				    addr.sin_addr.s_addr)
				if (++n >= MAX_SESSIONS_PER_SOURCE)
					break;
			} else if (j < 0)
				j = i;
		}

		if (n >= MAX_SESSIONS_PER_SOURCE) {
			if (!sessions[i].log ||
			    now < sessions[i].log ||
			    now - sessions[i].log >= min_delay) {
				syslog(SYSLOG_PRI_HI,
					"%s: per source limit reached",
					inet_ntoa(addr.sin_addr));
				sessions[i].log = now;
			}
			continue;
		}

		if (j < 0) {
			if (!log ||
			    now < log || now - log >= min_delay) {
				syslog(SYSLOG_PRI_HI,
					"%s: sessions limit reached",
					inet_ntoa(addr.sin_addr));
				log = now;
			}
			continue;
		}

		switch ((pid = fork())) {
		case -1:
			syslog(SYSLOG_PRI_ERROR, "%s: fork: %m",
				inet_ntoa(addr.sin_addr));
			break;

		case 0: {
			const char *from = inet_ntoa(addr.sin_addr);
			if (close(sock))
				return log_error("close");
			syslog(SYSLOG_PRI_LO, "Session from %s", from);
			if (dup2(new, 0) < 0 ||
			    dup2(new, 1) < 0 ||
			    dup2(new, 2) < 0)
				return log_error("dup2");
			if (close(new))
				return log_error("close");
			return session_process(from);
		}

		default:
			sessions[j].addr = addr.sin_addr;
			sessions[j].pid = pid;
			sessions[j].start = now;
			sessions[j].log = 0;
		}
	}
}
