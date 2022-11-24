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
#define TIMESTAMP_SIZE 0x20
		uint8_t buf[TIMESTAMP_SIZE + 0x2100 + hydro_secretbox_HEADERBYTES];
		uint8_t *pbuf = &buf[TIMESTAMP_SIZE];
		uint32_t len;
		n = read_loop(0, &len, sizeof(len));
		if (n != sizeof(len)) {
			if (n)
				log_error("read");
			break;
		}
		len = ntohl(len);
		if (len <= hydro_secretbox_HEADERBYTES || len > sizeof(buf) - TIMESTAMP_SIZE)
			goto fail_data;
		n = read_loop(0, pbuf, len);
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
		if (hydro_secretbox_decrypt(pbuf, pbuf, n, ++msg_id, "lkrg-net", kp_server.rx))
			goto fail_data;
		n -= hydro_secretbox_HEADERBYTES;

/* Sanitize */
		pbuf[n] = 0;
		uint8_t *p = &pbuf[strspn((char *)pbuf, "0123456789,")];
		if ((*p != '-' && *p != 'c') || p[1] != ';' || memchr(pbuf, '\n', n) != &pbuf[n - 1])
			goto fail_data; /* Assumes no CONFIG_PRINTK_CALLER */

/* Store */
		int m = snprintf((char *)buf, TIMESTAMP_SIZE, "%llu,", (unsigned long long)tv.tv_sec * 1000000 + tv.tv_usec);
		if (m < 0 || m >= TIMESTAMP_SIZE)
			continue; /* Shouldn't happen */
		pbuf = &buf[TIMESTAMP_SIZE - m];
		memmove(pbuf, buf, m);
		if (write_loop(fd, pbuf, m + n) != m + n)
			log_error("write");
	}

	close(fd);
	return !!n;

fail_data:
	close(fd);
	errno = 0;
	return log_error("Received bad data packet");
}
