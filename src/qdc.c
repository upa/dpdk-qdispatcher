#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_debug.h>

#include <qdispatcher.h>
#include <qdc.h>
#include <util.h>


static int init_unix_sock(void)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pr_err("failed to create unix domain socket: %s\n",
		       strerror(errno));
		return -1 * errno;
	}

	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, QDISPATCHER_SOCK_PATH, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		pr_err("failed to connect to %s: %s\n",
		       sun.sun_path, strerror(errno));
		close(fd);
		return -1 * errno;
	}

	return fd;
}

struct qdc {
	int fd;
	int qnum;
	struct rte_mempool *d_mp;	/* dispatcher's mempool */
	struct msg_register reg;

	/* callback handler for frame message */
	qdc_callback	cb;
	void		*cb_arg;
	pthread_t	cb_tid;
	int		cb_stop;
};

static int send_msg(int fd, struct msg_hdr *hdr, size_t size,
		    struct msg_reply *rep)
{
	struct pollfd x[1];
	int ret = 0;

	ret = write(fd, hdr, size);
	if (ret < 0) {
		pr_err("write failed: %s\n", strerror(errno));
		return -1 * errno;
	}

	x[0].fd = fd;
	x[0].events = POLLIN;

	/* wait reply */
	ret = poll(x, 1, 1000);	/* timeout 1 sec */
	if (ret < 0) {
		pr_err("poll failed: %s\n", strerror(errno));
		return -1 * errno;
	}

	if (ret == 0)
		return -ETIMEDOUT;

	ret = read(fd, rep, sizeof(*rep));
	if (ret < 0) {
		pr_err("read failed: %s\n", strerror(errno));
		return -1 * errno;
	}

	return 0;
}

static int do_register(qdc_t *qdc)
{
	struct msg_reply rep;
	int ret;

	qdc->fd = init_unix_sock();
	if (qdc->fd < 0)
		return qdc->fd;

	ret = send_msg(qdc->fd, (struct msg_hdr *)&qdc->reg, sizeof(qdc->reg),
		       &rep);
	if (ret < 0)
		return ret;

	if (rep.ret == 0)
		qdc->qnum = rep.qnum;

	ret = rep.ret;

	return ret;
}


qdc_t *qdc_register(struct rte_mempool *rx_mp,
		    uint16_t nb_txd, uint16_t nb_rxd,
		    struct rte_eth_txconf txconf,
		    struct rte_eth_rxconf rxconf,
		    struct rte_ether_addr mac)
{
	qdc_t *qdc;
	int ret;

	qdc = malloc(sizeof(*qdc));
	if (!qdc) {
		pr_err("failed to alloc qdc: %s\n", strerror(errno));
		return NULL;
	}
	memset(qdc, 0, sizeof(*qdc));
	
	strncpy(qdc->reg.rx_mp_name, rx_mp->name, RTE_MEMZONE_NAMESIZE);

	qdc->reg.hdr.type = QDISPATCHER_MSG_TYPE_REGISTER;
	qdc->reg.nb_txd = nb_txd;
	qdc->reg.nb_rxd = nb_rxd;
	qdc->reg.txconf = txconf;
	qdc->reg.rxconf = rxconf;
	qdc->reg.mac = mac;

	/* try register */
	ret = do_register(qdc);
	if (ret < 0) {
		pr_err("registration failed: %s\n", strerror(ret * -1));
		goto free_out;
	}

	return qdc;

free_out:
	free(qdc);
	return NULL;
}


int qdc_unregister(qdc_t *qdc)
{
	struct msg_unregister unreg;
	struct msg_reply rep;
	int ret, fd;
	void *r;

	/* stop cb thread */
	qdc->cb_stop = 1;
	pthread_join(qdc->cb_tid, &r);

	/* start to unregister this client */
	unreg.hdr.type = QDISPATCHER_MSG_TYPE_UNREGISTER;
	unreg.qnum = qdc->qnum;

	fd = init_unix_sock();
	if (fd < 0)
		return fd;

	ret = send_msg(fd, (struct msg_hdr *)&unreg, sizeof(unreg), &rep);
	if (ret < 0)
		return ret;

	if (rep.ret < 0)
		ret = rep.ret;

	return ret;
}


int qdc_qnum(qdc_t *qdc)
{
	return qdc->qnum;
}


void *qdc_frame_thread(void *arg)
{
	struct msg_frame *f;
	qdc_t *qdc = arg;
	char buf[2048];
	int ret;
	struct pollfd x[1];

	x[0].fd = qdc->fd;
	x[0].events = POLLIN;

	do {
		if (qdc->cb_stop)
			break;

		ret = poll(x, 1, 10);
		if (ret < 0) {
			pr_warn("poll error: %s\n", strerror(errno));
			break;
		}

		if (ret == 0)
			continue; /* timed out */

		ret = read(qdc->fd, buf, sizeof(buf));
		if (ret < 0) {
			pr_warn("read failed: %s\n", strerror(errno));
			break;
		}
		if (ret == 0)
			break; /* EOF */

		/* call cb function for this frame */
		f = (struct msg_frame *)buf;
		qdc->cb(f->frame, ret - sizeof(struct msg_hdr), qdc->cb_arg);

	} while (1);

	return NULL;
}

int qdc_register_frame_cb(qdc_t *qdc, qdc_callback cb, void *arg)
{
	qdc->cb = cb;
	qdc->cb_arg = arg;
	if (pthread_create(&qdc->cb_tid, NULL, qdc_frame_thread, qdc) < 0) {
		pr_err("failed to start frame cb thread: %s\n",
		       strerror(errno));
		return -1;
	}

	return 0;
}
