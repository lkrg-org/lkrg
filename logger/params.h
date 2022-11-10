/*
 * Global daemon parameters.
 */

/*
 * The address and port to listen on.
 */
#define DAEMON_ADDR			"0.0.0.0"	/* INADDR_ANY */
#define DAEMON_PORT			1515

/*
 * Limit the number of sessions we can handle at a time to reduce the impact of
 * connection flood DoS attacks.
 */
#define MAX_SESSIONS			1000
#define MAX_SESSIONS_PER_SOURCE		10
#define MAX_BACKLOG			5
#define MIN_DELAY			10

/*
 * How do we talk to syslogd?  These should be fine for most systems.
 */
#define SYSLOG_IDENT			"lkrg-logger"
#define SYSLOG_OPTIONS			LOG_PID
#define SYSLOG_FACILITY			LOG_DAEMON
#define SYSLOG_PRI_LO			LOG_INFO
#define SYSLOG_PRI_HI			LOG_NOTICE
#define SYSLOG_PRI_ERROR		LOG_CRIT
