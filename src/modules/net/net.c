/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Remote logging module
 *
 * Timeline:
 *  - Initial implementation: October - November 2022
 *  - Forward-port and publication: February 2024
 *
 * Author:
 *  - Solar Designer
 *
 * Copyright:
 *  - 2022, Binarly
 *  - 2024, Solar Designer
 */

#include "net.h"

#ifdef LKRG_WITH_NET

#include <linux/version.h>
#include <linux/moduleparam.h>

#include <linux/fs.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/inet.h>

#include <linux/time.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/clock.h> /* for local_clock(), was in sched.h before */
#endif

#include <linux/mutex.h>
#include <linux/workqueue.h>

#include <linux/console.h>

#include "hydrogen/hydrogen.c"

#include "../../p_lkrg_main.h"

static char net_server_addr[16];
module_param_string(net_server_addr, net_server_addr, sizeof(net_server_addr), 0);
MODULE_PARM_DESC(net_server_addr, "log server IPv4 address");

static ushort net_server_port = 514;
module_param(net_server_port, ushort, 0);
MODULE_PARM_DESC(net_server_port, "log server TCP port number [514 is default]");

static char net_server_pk[65];
module_param_string(net_server_pk, net_server_pk, sizeof(net_server_pk), 0);
MODULE_PARM_DESC(net_server_pk, "log server public key");

static __be32 net_server_addr_n;

static struct socket *sk;
static uint64_t msg_id;

static struct file *kmsg_file;
static loff_t kmsg_pos;

static uint8_t server_static_pk[hydro_kx_PUBLICKEYBYTES];
static uint8_t packet1[hydro_kx_N_PACKET1BYTES];
static hydro_kx_session_keypair kp_client;

/*
 * There are three cases:
 * - Below 5.10: we don't need exact value, but it's 8192;
 * - 5.10 to 6.2.x: we need exact value and it's 8192 and CONSOLE_EXT_LOG_MAX
 *   is defined by the kernel (so we don't override);
 * - 6.3+: we need exact value and it's actually PRINTK_MESSAGE_MAX 2048.
 * We check for 5.10+ rather than 6.3+ in order to pick the right value on
 * intermediary unreleased kernels between 6.2.x and 6.3 as well as with
 * possible backports of the 6.3+ change to older-numbered kernel branches.
 */
#ifndef CONSOLE_EXT_LOG_MAX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define CONSOLE_EXT_LOG_MAX 2048
#else
#define CONSOLE_EXT_LOG_MAX 8192
#endif
#endif

#define TIMESTAMPS_MAX (20 + 1 + 20 + 1)
static char buf[TIMESTAMPS_MAX + CONSOLE_EXT_LOG_MAX];
static uint8_t ciphertext[4 + sizeof(buf) + hydro_secretbox_HEADERBYTES];
static size_t buf_resend_size;

static void log_issue(int err)
{
	static DEFINE_RATELIMIT_STATE(state, 180 * HZ, 3);
	if (___ratelimit(&state, "LKRG: ISSUE: Net: Rate limit"))
		p_print_log(P_LOG_ISSUE, "Net: Connection error %d", err);
}

static void disconnect(void)
{
	if (sk) {
		sock_release(sk);
		sk = NULL;
	}
}

static bool try_send_raw(void *buf, size_t count);

static void maybe_reconnect(void)
{
	static unsigned long last_time;
	struct sockaddr_in saddr = {};
	int err;

	if (sk)
		return;

	if (last_time && jiffies - last_time < 10 * HZ)
		return;
	last_time = jiffies;

	if ((err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sk)) < 0) {
		sk = NULL;
		log_issue(err);
		return;
	}

	sk->sk->sk_sndtimeo = HZ;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	tcp_sock_set_nodelay(sk->sk);
#else
	int one = 1;
	kernel_setsockopt(sk, SOL_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
#endif

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(net_server_port);
	saddr.sin_addr.s_addr = net_server_addr_n;
	switch ((err = sk->ops->connect(sk,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	    (struct sockaddr_unsized *)
#else
	    (struct sockaddr *)
#endif
	    &saddr, sizeof(saddr), O_WRONLY))) {
	case 0:
	case -EINPROGRESS:
		break;
	default:
		disconnect();
		log_issue(err);
		return;
	}

	hydro_kx_n_1(&kp_client, packet1, NULL, server_static_pk);
	try_send_raw(packet1, sizeof(packet1));

	msg_id = 0;
}

static bool try_send_raw(void *buf, size_t count)
{
	struct msghdr msg = {};
	struct kvec vec;

	if (!sk)
		return false;

	vec.iov_base = buf;
	vec.iov_len = count;
	do {
		int sent = kernel_sendmsg(sk, &msg, &vec, 1, vec.iov_len);
		if (sent <= 0) {
			disconnect();
			log_issue(sent);
			return false;
		}
/*
 * We have to either send the whole message or close the connection.  Sending a
 * partial message and then proceeding to send the next message isn't an option
 * as it'd get the receiver out of sync with us.
 */
		vec.iov_base += sent;
		vec.iov_len -= sent;
	} while (vec.iov_len > 0);

	return true;
}

static bool try_send(void *buf, size_t count)
{
	if (!sk)
		return false;

	if (count > sizeof(ciphertext) - 4 - hydro_secretbox_HEADERBYTES)
		count = sizeof(ciphertext) - 4 - hydro_secretbox_HEADERBYTES;

	hydro_secretbox_encrypt(&ciphertext[4], buf, count, ++msg_id, "lkrg-net", kp_client.tx);
	count += hydro_secretbox_HEADERBYTES;
	ciphertext[0] = (count >> 24) & 0xff;
	ciphertext[1] = (count >> 16) & 0xff;
	ciphertext[2] = (count >> 8) & 0xff;
	ciphertext[3] = count & 0xff;

	return try_send_raw(ciphertext, 4 + count);
}

static bool try_send_reconnect(void *buf, size_t count)
{
	bool sent = try_send(buf, count);
	if (!sent) {
		maybe_reconnect();
		sent = try_send(buf, count);
	}
	return sent;
}

static void work_do(struct work_struct *work);

static DECLARE_WORK(work, work_do);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
struct devkmsg_user {
	atomic64_t seq;
	struct ratelimit_state rs;
	struct mutex lock;
	char buf[CONSOLE_EXT_LOG_MAX];
};
#endif

static void work_do(struct work_struct *work)
{
	static DEFINE_MUTEX(lock);
	bool sent = true;
	unsigned int retry = 0;

/*
 * If we cannot acquire the mutex right away, then most likely we're still in
 * the loop below and thus would also process any extra messages that our work
 * may have been re-queued to process.  There's, however, a slight chance that
 * we're already exiting the loop and thus wouldn't notice some new messages.
 * To avoid or deal with the latter case, the work should only be invoked once
 * at a time or it should be re-queued once in a while.  For safety, we need to
 * exit from here rather than stall a concurrent worker thread or access shared
 * variables without locking.
 */
	if (!mutex_trylock(&lock))
		return;

	if (buf_resend_size)
		if ((sent = try_send_reconnect(buf, buf_resend_size)))
			buf_resend_size = 0;

	while (sent || (retry > 0 && retry < 10)) {
		u64 usec_since_epoch, usec_since_boot;
		ssize_t m, n;
		char *pbuf;

#if defined(TIME_T_MAX) && !defined(TIME64_MAX)
		struct timespec ts;
		ktime_get_real_ts(&ts);
#else
		struct timespec64 ts;
		ktime_get_real_ts64(&ts);
#endif

		usec_since_epoch = ts.tv_nsec;
		do_div(usec_since_epoch, 1000);
		usec_since_epoch += ts.tv_sec * (u64)1000000;

/*
 * local_clock() is the function used by printk().  We use the same one to have
 * comparable timestamps.  We might not be on the same CPU and some clock drift
 * between CPUs is possible, but the same issue applies to timestamps seen on
 * different kmsg records anyway.
 */
		usec_since_boot = local_clock();
		do_div(usec_since_boot, 1000);

		m = snprintf(buf, TIMESTAMPS_MAX + 1, "%llu,%llu,", usec_since_epoch, usec_since_boot);
		if (m < 0 || m > TIMESTAMPS_MAX)
			break; /* Shouldn't happen */
		pbuf = buf + m;

/*
 * Assume we're running in a kthread, so with addr_limit = KERNEL_DS on < 5.10
 * and thus don't need to use kernel_read().  If we're on 5.10+, kernel_read()
 * wouldn't have helped anyway (would have triggered a runtime warning), so we
 * expect a -EFAULT, which we then handle.
 */
		n = kmsg_file->f_op->read(kmsg_file, pbuf, sizeof(buf) - TIMESTAMPS_MAX, &kmsg_pos);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		if (n == -EFAULT) {
			struct devkmsg_user *user = kmsg_file->private_data;
			char *end = memchr(user->buf, '\n', sizeof(user->buf));
			if (end && end > user->buf && end - user->buf + 1 <= sizeof(buf) - TIMESTAMPS_MAX) {
				n = end - user->buf + 1;
				memcpy(pbuf, user->buf, n);
			}
		}
#endif
/*
 * -EPIPE indicates "our last seen message is gone, return error and reset" as
 * the comment in devkmsg_read() says.
 */
		if (n == -EPIPE)
			retry++;
		else
			retry = 0;
		sent = false;
		if (n > 0)
			if (!(sent = try_send_reconnect(buf, m + n)))
				buf_resend_size = m + n;
	}

	mutex_unlock(&lock);
}

void lkrg_queue_net(void)
{
	if (kmsg_file)
		queue_work(system_unbound_wq, &work);
}

static void write_msg(struct console *con, const char *str, unsigned int len)
{
	lkrg_queue_net();
}

static struct console lkrg_console = {
	.name = "lkrg",
	.flags = CON_ENABLED,
	.write = write_msg
};

void lkrg_register_net(void)
{
	const char *end;

	if (!net_server_addr[0])
		return;

	if (!in4_pton(net_server_addr, -1, (u8 *)&net_server_addr_n, -1, &end) || *end) {
		p_print_log(P_LOG_FAULT, "Net: Can't parse 'net_server_addr'");
		return;
	}

	if (!net_server_pk[0] ||
	    hydro_init() /* Currently can't fail */ ||
	    hydro_hex2bin(server_static_pk, sizeof(server_static_pk), net_server_pk, 64, NULL, NULL) != 32) {
		p_print_log(P_LOG_FAULT, "Net: Can't parse 'net_server_pk'");
		return;
	}

	kmsg_file = filp_open("/dev/kmsg", O_RDONLY | O_NONBLOCK, 0);
	if (!kmsg_file) {
		p_print_log(P_LOG_FAULT, "Net: Can't open '/dev/kmsg'");
		return;
	}

	kmsg_file->f_op->llseek(kmsg_file, 0, SEEK_END);

	/* Optional, could also connect on first message */
	maybe_reconnect();

	register_console(&lkrg_console);
}

void lkrg_deregister_net(void)
{
	if (kmsg_file) {
		unregister_console(&lkrg_console);
		flush_work(&work);
		cancel_work_sync(&work); /* Redundant unless the work re-queues */
		filp_close(kmsg_file, NULL);
		kmsg_file = NULL;
		disconnect();
	}
}

#endif
