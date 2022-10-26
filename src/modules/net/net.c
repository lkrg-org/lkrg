#include <linux/version.h>
#include <linux/moduleparam.h>

#include <linux/fs.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/inet.h>

#include <linux/mutex.h>
#include <linux/workqueue.h>

#include <linux/console.h>

#include "hydrogen/hydrogen.c"

static char net_server_addr[16];
module_param_string(net_server_addr, net_server_addr, sizeof(net_server_addr), 0);
MODULE_PARM_DESC(net_server_addr, "log server IPv4 address");

static ushort net_server_port = 1515;
module_param(net_server_port, ushort, 0);
MODULE_PARM_DESC(net_server_port, "log server TCP port number [1515 is default]");

static char net_server_pk[65];
module_param_string(net_server_pk, net_server_pk, sizeof(net_server_pk), 0);
MODULE_PARM_DESC(net_server_pk, "log server public key");

static __be32 net_server_addr_n;

static struct socket *sk;

static struct file *kmsg_file;
static loff_t kmsg_pos;

static uint8_t server_static_pk[hydro_kx_PUBLICKEYBYTES];
static uint8_t packet1[hydro_kx_N_PACKET1BYTES];
static hydro_kx_session_keypair kp_client;

#ifdef CONSOLE_EXT_LOG_MAX
static char buf[CONSOLE_EXT_LOG_MAX];
#else
static char buf[0x2000];
#endif
static uint8_t ciphertext[4 + sizeof(buf) + hydro_secretbox_HEADERBYTES];

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
	struct sockaddr_in saddr = {};

	if (sk)
		return;

	if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sk) < 0) {
		sk = NULL;
		return;
	}

	sk->sk->sk_sndtimeo = HZ;

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(net_server_port);
	saddr.sin_addr.s_addr = net_server_addr_n;
	switch (sk->ops->connect(sk, (struct sockaddr *)&saddr, sizeof(saddr), O_WRONLY)) {
	case 0:
	case -EINPROGRESS:
		break;
	default:
		disconnect();
		return;
	}

	hydro_kx_n_1(&kp_client, packet1, NULL, server_static_pk);
	try_send_raw(packet1, sizeof(packet1));
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

	hydro_secretbox_encrypt(&ciphertext[4], buf, count, 0, "lkrg-net", kp_client.tx);
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
	char *pbuf;
	ssize_t n;
	bool sent;
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

	do {
/*
 * Assume we're running in a kthread, so with addr_limit = KERNEL_DS on < 5.10
 * and thus don't need to use kernel_read().  If we're on 5.10+, kernel_read()
 * wouldn't have helped anyway (would have triggered a runtime warning), so we
 * expect a -EFAULT, which we then handle.
 */
		n = kmsg_file->f_op->read(kmsg_file, buf, sizeof(buf), &kmsg_pos);
		pbuf = buf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		if (n == -EFAULT) {
			struct devkmsg_user *user = kmsg_file->private_data;
			char *end = memchr(user->buf, '\n', sizeof(user->buf));
			if (end) {
				n = end - user->buf + 1;
				pbuf = user->buf;
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
			sent = try_send_reconnect(pbuf, n);
	} while (sent || (retry > 0 && retry < 10));

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
	if (!net_server_addr[0] || !net_server_pk[0] ||
	    hydro_init() ||
	    hydro_hex2bin(server_static_pk, sizeof(server_static_pk), net_server_pk, 64, NULL, NULL) != 32)
		return;

	kmsg_file = filp_open("/dev/kmsg", O_RDONLY | O_NONBLOCK, 0);

	if (!kmsg_file)
		return;

	kmsg_file->f_op->llseek(kmsg_file, 0, SEEK_END);

	net_server_addr_n = in_aton(net_server_addr);

	/* Optional, could also connect on first message */
	maybe_reconnect();

	register_console(&lkrg_console);
}

void lkrg_deregister_net(void)
{
	unregister_console(&lkrg_console);
	flush_work(&work);
	cancel_work_sync(&work); /* Redundant unless the work re-queues */
	if (kmsg_file)
		filp_close(kmsg_file, NULL);
	disconnect();
}
