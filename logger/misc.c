/*
 * Miscellaneous system and library call wrappers.
 *
 * Initially written for popa3d, reused for LKRG logger with various changes
 * Copyright (c) 1998-2022 Solar Designer
 */

#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "misc.h"
#include "params.h"

ssize_t read_loop(int fd, void *buffer, size_t count)
{
	ssize_t offset, block;

	errno = 0;

	offset = 0;
	while (count > 0 && count <= SSIZE_MAX) {
		block = read(fd, (char *)buffer + offset, count);

		if (block < 0)
			return block;
		if (!block)
			return offset;

		offset += block;
		count -= block;
	}

	return offset;
}

ssize_t write_loop(int fd, const void *buffer, size_t count)
{
	ssize_t offset, block;

	errno = 0;

	offset = 0;
	while (count > 0 && count <= SSIZE_MAX) {
		block = write(fd, (char *)buffer + offset, count);

		if (block < 0)
			return block;
		if (!block)
			return offset;

		offset += block;
		count -= block;
	}

	return offset;
}

int log_error(const char *s)
{
	if (errno)
		syslog(SYSLOG_PRI_ERROR, "%s: %m", s);
	else if (!strcmp(s, "read") || !strcmp(s, "write"))
		syslog(SYSLOG_PRI_ERROR, "%s: Partial data", s);
	else
		syslog(SYSLOG_PRI_ERROR, "%s", s);
	return 1;
}
