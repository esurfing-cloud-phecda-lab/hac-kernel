#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kvm_host.h>

#include "ktcp.h"
#include "dsm-util.h"

struct ktcp_hdr {
	size_t length;
	tx_add_t tx_add;
	short short_field;
} __attribute__((packed));

// 16 is for sizeof(struct dsm_request)
#define KTCP_BUFFER_SIZE (sizeof(struct ktcp_hdr) + max(PAGE_SIZE_TRANSFER, 16))

static int __ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags)
{
	struct kvec vec;
	int len, written = 0, left = length;
	int ret;

	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = flags,
	};

repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char *)buffer + written;

	len = kernel_sendmsg(sock, &msg, &vec, 1, left);
	if (len == -EAGAIN || len == -ERESTARTSYS) {
		pr_err("eagin __ktcp_send repeat_send length=%lu len=%d left=%d written=%d txid=%d\n", length, len, left, written,((struct ktcp_hdr*)buffer)->tx_add.txid);
		goto repeat_send;
	}
	if (len > 0) {
		written += len;
		left -= len;
		if (left != 0) {
			pr_err("left not zero __ktcp_send repeat_send length=%lu len=%d left=%d written=%d txid=%d\n", length, len, left, written,((struct ktcp_hdr*)buffer)->tx_add.txid);
			goto repeat_send;
		}
	}
	dsm_debug_ktcp("__ktcp_send repeat_send length=%lu len=%d left=%d written=%d txid=%d\n", length, len, left, written,((struct ktcp_hdr*)buffer)->tx_add.txid);

	ret = written != 0 ? written : len;
	if (ret > 0 && ret != length) {
		pr_err("ktcp_send send %d bytes which expected_size=%lu bytes\n", ret, length);
	}

	if (ret < 0) {
		pr_err("ktcp_send %d\n", ret);
	}

	return ret;
}


int ktcp_send(struct ktcp_cb *cb, const char *buffer, size_t length,
		unsigned long flags, const tx_add_t *tx_add)
{
	int ret;
	struct ktcp_hdr hdr;
	char *local_buffer;

	hdr.tx_add = *tx_add;
	hdr.length = sizeof(hdr) + length;

	local_buffer = kzalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		return -ENOMEM;
	}
	memcpy(local_buffer, &hdr, sizeof(hdr));
	memcpy(local_buffer + sizeof(hdr), buffer, length);

	// Get current address access limitdo
	// print_hex_dump(KERN_INFO, "__ktcp_send: ", DUMP_PREFIX_NONE,
	// 		       32, 1, local_buffer, 32, 1);
	dsm_debug_ktcp("ktcp_send hdr.tx_add.txid=%d\n", tx_add->txid);
	ret = __ktcp_send(cb->socket, local_buffer, KTCP_BUFFER_SIZE, flags);
	
	// Retrieve address access limit
	kfree(local_buffer);
	return ret < 0 ? ret : length;
}

static int __ktcp_receive(struct socket *sock, char *buffer, size_t expected_size,
		unsigned long flags)
{
	struct kvec vec;
	int ret;
	int len = 0;
	
	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = flags,
	};

	if (expected_size == 0) {
		return 0;
	}

read_again:
	vec.iov_len = expected_size - len;
	vec.iov_base = buffer + len;
	ret = kernel_recvmsg(sock, &msg, &vec, 1, expected_size - len, flags);

	if (ret == 0) {
		return len;
	}

	// Non-blocking on the first try
	if (len == 0 && (flags & SOCK_NONBLOCK) &&
			(ret == -EWOULDBLOCK || ret == -EAGAIN)) {
		return ret;
	}

	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto read_again;
	}
	else if (ret < 0) {
		printk(KERN_ERR "kernel_recvmsg %d\n", ret);
		return ret;
	}
	len += ret;
	if (len != expected_size) {
		//printk(KERN_WARNING "ktcp_receive receive %d bytes which expected_size=%lu bytes, read again", len, expected_size);
		goto read_again;
	}

	return len;
}

static inline bool once(void)
{
	static bool happend = false;
	if(happend){
		return false;
	}else{
		happend = true;
		return true;
	}
}

int ktcp_receive(struct ktcp_cb *cb, char *buffer, unsigned long flags,
		tx_add_t *tx_add)
{
	struct ktcp_hdr hdr;
	int ret;
	uint32_t usec_sleep = 0;
	char *local_buffer;

	BUG_ON(cb == NULL || buffer == NULL || tx_add == NULL);

repoll:
	local_buffer = kzalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		ret = -ENOMEM;
		printk(KERN_ERR "%s: kzalloc error \n", __func__);
		goto out;
	}
	ret = __ktcp_receive(cb->socket, local_buffer, KTCP_BUFFER_SIZE, flags);

	if (ret < 0) {
		if(usec_sleep>=1000){
			pr_err("ret =%d tx_id=%d usec_sleep=%u flags=%lu\n", ret, tx_add->txid, usec_sleep, flags);
			if(once())
				dump_stack();
		}
		if (ret == -EAGAIN) {
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			// usleep_range(usec_sleep, usec_sleep);
			udelay(usec_sleep);
			kfree(local_buffer);
			goto repoll;
		}
		pr_err("%s error: %d\n", __func__, ret);
		kfree(local_buffer);
		goto out;
	}
	usec_sleep = 0;
	if(usec_sleep>=1000)
		pr_err("ret zero finally. tx_id=%d usec_sleep=%u flags=%lu\n", tx_add->txid, usec_sleep, flags);
	memcpy(&hdr, local_buffer, sizeof(hdr));
	dsm_debug_ktcp("received remote txid: %d local txid: %d\n", hdr.tx_add.txid, tx_add->txid);
	if (hdr.tx_add.txid != tx_add->txid && tx_add->txid != 0xFF){
		pr_err("if -> insert_into_recv_buf\n");
		ret = -ENOMEM;
		goto out;
	}
	size_t real_length;
	real_length = hdr.length - sizeof(struct ktcp_hdr);
	memcpy(buffer, (char *)local_buffer + sizeof(struct ktcp_hdr), real_length);
	*tx_add = hdr.tx_add;
	kfree(local_buffer);

out:
	return ret < 0 ? ret : hdr.length - sizeof(struct ktcp_hdr);
}

static int ktcp_create_cb(struct ktcp_cb **cbp)
{
	struct ktcp_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	*cbp = cb;
	return 0;
}

int ktcp_connect(const char *host, const char *port, struct ktcp_cb **conn_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *conn_socket;

	if (host == NULL || port == NULL || conn_cb == NULL) {
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb fail, return %d\n",
				__func__, ret);
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
	if (ret < 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	if((ret=kstrtol(port, 10, &portdec))!=0){
		printk(KERN_ERR "%s: kstrtol error: port=%s\n", __func__, port);
		return ret;
	}
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

re_connect:
	ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr,
			sizeof(saddr), O_RDWR);
	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto re_connect;
	}

	if (ret && (ret != -EINPROGRESS)) {
		printk(KERN_ERR "%s: connct failed, return %d\n", __func__, ret);
		sock_release(conn_socket);
		return ret;
	}

	cb->socket = conn_socket;
	mutex_init(&cb->lock);
	*conn_cb = cb;
	return SUCCESS;
}

int ktcp_listen(const char *host, const char *port, struct ktcp_cb **listen_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *listen_socket;

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	if((ret=kstrtol(port, 10, &portdec))!=0){
		printk(KERN_ERR "%s: kstrtol error: port=%s\n", __func__, port);
		return ret;
	}
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

	ret = listen_socket->ops->bind(listen_socket, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0) {
		printk(KERN_ERR "%s: bind failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		return ret;
	}

	ret = listen_socket->ops->listen(listen_socket, DEFAULT_BACKLOG);
	if (ret != 0) {
		printk(KERN_ERR "%s: listen failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		return ret;
	}

	cb->socket = listen_socket;
	*listen_cb = cb;
	return SUCCESS;
}

int ktcp_accept(struct ktcp_cb *listen_cb, struct ktcp_cb **accept_cb, unsigned long flag)
{
	int ret;
	struct ktcp_cb *cb;
	struct socket *listen_socket, *accept_socket;

	if (listen_cb == NULL || (listen_socket = listen_cb->socket) == NULL) {
		printk(KERN_ERR "%s: null listen_cb\n", __func__);
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
	}

	ret = sock_create_lite(listen_socket->sk->sk_family, listen_socket->sk->sk_type,
			listen_socket->sk->sk_protocol, &accept_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}

re_accept:
	ret = listen_socket->ops->accept(listen_socket, accept_socket, flag, true);
	if (ret == -ERESTARTSYS) {
		if (kthread_should_stop())
			return ret;
		goto re_accept;
	}
	// When setting SOCK_NONBLOCK flag, accept return this when there's nothing in waiting queue.
	if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
		sock_release(accept_socket);
		accept_socket = NULL;
		return ret;
	}
	if (ret < 0) {
		printk(KERN_ERR "%s: accept failed, return %d\n", __func__, ret);
		sock_release(accept_socket);
		accept_socket = NULL;
		return ret;
	}

	accept_socket->ops = listen_socket->ops;
	cb->socket = accept_socket;
	mutex_init(&cb->lock);
	*accept_cb = cb;

	return SUCCESS;
}

int ktcp_release(struct ktcp_cb *conn_cb)
{
	if (conn_cb == NULL) {
		return -EINVAL;
	}

	sock_release(conn_cb->socket);
	return SUCCESS;
}
