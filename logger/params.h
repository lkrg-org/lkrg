/*
 * Global daemon parameters.
 */

/*
 * Our name to use when talking to various interfaces.
 */
#define DAEMON_NAME			"lkrg-logger"

/*
 * The address and port to listen on.
 */
#define DAEMON_ADDR			"0.0.0.0"	/* INADDR_ANY */
#define DAEMON_PORT			514

/*
 * Limit the number of sessions we can handle at a time to reduce the impact of
 * connection flood DoS attacks.
 */
#define MAX_SESSIONS			1000
#define MAX_SESSIONS_PER_SOURCE		10
#define MAX_BACKLOG			5
#define MIN_DELAY			10

/*
 * Directory where to store the received logs.
 */
#define LOG_PATH			"/var/log/" DAEMON_NAME

/*
 * How do we talk to syslogd?  These should be fine for most systems.
 */
#define SYSLOG_IDENT			DAEMON_NAME
#define SYSLOG_OPTIONS			LOG_PID
#define SYSLOG_FACILITY			LOG_DAEMON
#define SYSLOG_PRI_LO			LOG_INFO
#define SYSLOG_PRI_HI			LOG_NOTICE
#define SYSLOG_PRI_ERROR		LOG_CRIT
