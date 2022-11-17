#include <stdlib.h> /* for getenv() */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <sys/time.h>

#include "hydrogen/hydrogen.c"

#include "misc.h"
#include "session.h"

static hydro_kx_keypair server_static_kp;
static uint8_t packet1[hydro_kx_N_PACKET1BYTES];
static hydro_kx_session_keypair kp_server;

int session_prepare(void)
{
	const char *pk = getenv("LKRG_LOGGER_PK");
	const char *sk = getenv("LKRG_LOGGER_SK");
	if (!pk || !sk ||
	    hydro_init() /* Currently can't fail */ ||
	    hydro_hex2bin(server_static_kp.pk, sizeof(server_static_kp.pk), pk, 64, NULL, NULL) != 32 ||
	    hydro_hex2bin(server_static_kp.sk, sizeof(server_static_kp.sk), sk, 64, NULL, NULL) != 32) {
		errno = 0;
		return log_error("Invalid LKRG_LOGGER_PK and/or LKRG_LOGGER_SK");
	}
	return 0;
}

int session_process(const char *from)
{
	int fd;
	ssize_t n;
	uint64_t msg_id = 0;

	if (read_loop(0, packet1, sizeof(packet1)) != sizeof(packet1))
		return log_error("read");

	if (hydro_kx_n_2(&kp_server, packet1, NULL, &server_static_kp)) {
		errno = 0;
		return log_error("Received bad handshake packet");
	}

	{
		char fn[24];
		snprintf(fn, sizeof(fn), "log/%s", from);
		fd = open(fn, O_CREAT | O_WRONLY | O_APPEND, 0640);
		if (fd < 0)
			return log_error("open");
	}

	while (1) {
/* Receive */
		uint8_t buf[0x2100 + hydro_secretbox_HEADERBYTES];
		uint32_t len;
		n = read_loop(0, &len, sizeof(len));
		if (n != sizeof(len)) {
			if (n)
				log_error("read");
			break;
		}
		len = ntohl(len);
		if (len <= hydro_secretbox_HEADERBYTES || len > sizeof(buf))
			goto fail_data;
		n = read_loop(0, buf, len);
		if (n != len) {
			n = -1;
			log_error("read");
			break;
		}

/* Timestamp */
		struct timeval tv;
		if (gettimeofday(&tv, NULL)) {
			n = -1;
			log_error("gettimeofday");
			break;
		}

/* Decrypt */
		if (hydro_secretbox_decrypt(buf, buf, n, ++msg_id, "lkrg-net", kp_server.rx))
			goto fail_data;
		n -= hydro_secretbox_HEADERBYTES;

/* Store */
		char tvbuf[22];
		snprintf(tvbuf, sizeof(tvbuf), "%llu,", (unsigned long long)tv.tv_sec * 1000000 + tv.tv_usec);
		if (write_loop(fd, tvbuf, strlen(tvbuf)) != (ssize_t)strlen(tvbuf))
			log_error("write");
		if (write_loop(fd, buf, n) != n)
			log_error("write");
	}

	close(fd);
	return !!n;

fail_data:
	close(fd);
	errno = 0;
	return log_error("Received bad data packet");
}
