#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

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
	int qnum;
	struct rte_mempool *d_mp;	/* dispatcher's mempool */
	struct msg_register reg;

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
	int ret, fd;

	fd = init_unix_sock();
	if (fd < 0)
		return fd;

	ret = send_msg(fd, (struct msg_hdr *)&qdc->reg, sizeof(qdc->reg),
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
