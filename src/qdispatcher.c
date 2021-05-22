#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_debug.h>

#include <qdispatcher.h>
#include <util.h>

static int debug;	/* for pr_debug */

/* structure describing client process */
struct client {
	int fd;		/* accepted socket */
	int qnum;	/* queue number for the client */
	struct msg_register 	reg;

	struct rte_mempool	*rx_mp;	/* rx mempool in the client */
	struct rte_flow		*flow;	/* mac -> queue flow rule */
};

/* structure describing qdispatcher process */
struct qdispatcher {
	int portid;	/* physical port id */
	struct rte_eth_conf 	conf;
	struct rte_eth_dev_info	info;
	struct rte_mempool	*default_rx_pool;

	struct rte_flow		*flow;	/* flow for broadcast/multicast*/

	int fd;	/* unix domain socket fd */

	int nqueues;			/* # of queues enabled */
	struct client **clients;	/* number of nqueues array of
					 * struct client
					 * pointers. each index
					 * indicates a queue number
					 * for the client.
					 */
	pthread_mutex_t	clients_lock;
};

static struct qdispatcher qd;


char *mac_addr(struct rte_ether_addr *mac)
{
	static char m[32];
	rte_ether_format_addr(m, sizeof(m), mac);
	return m;
}

/**** flow rule *****/
struct rte_flow *install_dst_mac_queue_flow(struct rte_ether_addr dst_mac,
					    struct rte_ether_addr dst_mask,
					    uint16_t qnum)
{
	struct rte_flow_item item[2];	/* 0 is mac, 1 is end item */
	struct rte_flow_action act[2];	/* 0 is queue, 1 is end item */
	struct rte_flow_error err;

	struct rte_flow_item_eth eth, mask;
	struct rte_flow_action_queue queue;
	struct rte_flow *flow;

	struct rte_flow_attr attr = {
		.group 		= 0,
		.priority	= 2,
		.ingress	= 1,
		.egress		= 0,
		.transfer	= 0,
	};

	memset(item, 0, sizeof(item));
	memset(act, 0, sizeof(act));

	/* matching eth dst mac */
	item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	item[0].spec = &eth;
	item[0].last = NULL;
	item[0].mask = &mask;
	memset(&eth, 0, sizeof(eth));
	memset(&mask, 0, sizeof(mask));
	eth.hdr.d_addr = dst_mac;
	mask.hdr.d_addr = dst_mask;

	item[1].type = RTE_FLOW_ITEM_TYPE_END;

	/* action, redirect to the specified queue */
	act[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	act[0].conf = &queue;
	queue.index = qnum;

	act[1].type = RTE_FLOW_ACTION_TYPE_END;

	flow = rte_flow_create(qd.portid, &attr, item, act, &err);
	if (!flow) {
		pr_err("failed to create flow: port %d q %d mac %s "
		       "rte_errno:%s type:%d message:%s\n",
		       qd.portid, qnum, mac_addr(&dst_mac),
		       rte_strerror(rte_errno), err.type, err.message);
		return NULL;
	}

	return 0;
}


int install_client_flow(struct client *c)
{
	struct rte_ether_addr mask;

	memset(&mask, 0xFF, sizeof(mask));	/* all bit 1 */
	c->flow = install_dst_mac_queue_flow(c->reg.mac, mask, c->qnum);

	if (!c->flow)
		return -1;

	return 0;
}

int install_bm_queue_flow(struct qdispatcher *qd)
{
	struct rte_ether_addr mac, mask;

	mac.addr_bytes[0] = RTE_ETHER_GROUP_ADDR;
	mask.addr_bytes[0] = RTE_ETHER_GROUP_ADDR;

	qd->flow = install_dst_mac_queue_flow(mac, mask, 0);

	if (!qd->flow)
		return -1;

	return 0;
}

/**** restart the port ****/
static int restart_port(struct qdispatcher *qd)
{
	int ret, n;
	uint16_t max_txd = 512, max_rxd = 512;
	struct rte_flow_error err;

	/* stop, configure, queue stup, and start*/

	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (c) {
			max_txd = max(max_txd, c->reg.nb_txd);
			max_rxd = max(max_rxd, c->reg.nb_rxd);
		}
	}

	/* stop */
	ret = rte_eth_dev_stop(qd->portid);
	if (ret < 0) {
		pr_err("failed to stop port %d\n", qd->portid);
		return ret;
	}

	/* flush all flows */
	ret = rte_flow_flush(qd->portid, &err);
	if (ret < 0) {
		pr_err("failed to flush flow: port %d "
		       "rte_errno: %s type: %d mesage:%s\n",
		       qd->portid, rte_strerror(rte_errno),
		       err.type, err.message);
	}

	/* configure port */
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(qd->portid, &max_txd, &max_rxd);
	if (ret < 0) {
		pr_err("failed to adjust desc on port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
		return -EINVAL;
	}

	ret = rte_eth_dev_configure(qd->portid, qd->nqueues, qd->nqueues,
				    &qd->conf);
	if (ret < 0) {
		pr_err("failed to configure port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
		return -EINVAL;
	}

	/* configure queues including queue 0 for bm frames */
	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		struct rte_eth_txconf txconf;
		struct rte_eth_rxconf rxconf;
		struct rte_mempool *rx_mp;
		uint16_t nb_txd, nb_rxd;

		if (!c) {
			/* this queue is not used. so setup it with default */
			rx_mp = qd->default_rx_pool;
			nb_txd = 512;
			nb_rxd = 512;
			txconf = qd->info.default_txconf;
			rxconf = qd->info.default_rxconf;
		} else {
			rx_mp = c->rx_mp;
			nb_txd = c->reg.nb_txd;
			nb_rxd = c->reg.nb_rxd;
			txconf = c->reg.txconf;
			rxconf = c->reg.rxconf;
		}

		pr_info("q=%d txd %u rxd %u rx-mp %s %s\n",
			n, nb_txd, nb_rxd, rx_mp->name,
			(n == 0) ? "bm frames" :
			(c) ? mac_addr(&c->reg.mac) : "unused");

		ret = rte_eth_tx_queue_setup(qd->portid, n, nb_txd,
					     SOCKET_ID_ANY, &txconf);
		if (ret < 0) {
			pr_err("failed to configure tx q %d: %s\n",
			       n, rte_strerror(rte_errno));
		}

		ret = rte_eth_rx_queue_setup(qd->portid, n, nb_rxd,
					     SOCKET_ID_ANY, &rxconf, rx_mp);
		if (ret < 0) {
			pr_err("failed to configure rx q %d: %s\n",
			       n, rte_strerror(rte_errno));
		}
	}

	/* start */
	ret = rte_eth_dev_start(qd->portid);
	if (ret < 0) {
		pr_err("failed to start port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
		return -EINVAL;
	}

	/* install flows for passsing unicast frames to a
	 * corresponding queue. and, stop unused queues */
	for (n = 1; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (c) {
			install_client_flow(c);
		} else {
			rte_eth_dev_tx_queue_stop(qd->portid, n);
			rte_eth_dev_rx_queue_stop(qd->portid, n);
		}
	}

	/* install a flow for passing broadcast/multicast frames to
	 * queue 0. the frams are copied to all clients via unix
	 * sockets */
	install_bm_queue_flow(qd);

	pr_info("restart port %d done\n", qd->portid);

	return 0;
}

/**** handle register ****/

struct client *create_client_from_register(int fd,
					   struct msg_register *reg, int *ret)
{
	struct client *c;

	c = malloc(sizeof(*c));
	if (!c) {
		pr_err("failed to alloc memory for client: %s\n",
		       strerror(errno));
		*ret = errno;
		return NULL;
	}
	memset(c, 0, sizeof(*c));

	c->rx_mp = rte_mempool_lookup(reg->rx_mp_name);
	if (!c->rx_mp) {
		pr_err("rx_mp_name %s not found\n", reg->rx_mp_name);
		*ret = -ENOENT;
		goto free_out;
	}

	c->fd = fd;
	c->reg = *reg;
	*ret = 0;

	return c;

free_out:
	free(c);
	return NULL;
}

static void send_reply(int fd, int ret, int qnum)
{
	struct msg_reply rep;
	int r;

	pr_debug("ret %d qnum %d\n", ret, qnum);

	rep.hdr.type = QDISPATCHER_MSG_TYPE_REPLY;
	rep.ret = ret;
	rep.qnum = qnum;
	
	r = write(fd, &rep, sizeof(rep));
	if (r < 0)
		pr_err("write failed: %s\n", strerror(errno));
}

static void handle_register(struct qdispatcher *qd, int fd,
			    struct msg_hdr *hdr)
{
	struct msg_register *reg = (struct msg_register *)hdr;
	struct client *c;
	int n, q, ret = 0;

	c = create_client_from_register(fd, reg, &ret);
	if (!c || ret != 0) {
		pr_err("failed to add client\n");
		goto out;
	}

	/* find an available queue number for this client. queue 0 is
	 * reserved to receive broadcast/muticast frames by
	 * qdispatcher. so, find the available queue from 1.
	 */
	for (q = -1, n = 1; n < qd->nqueues; n++) {
		if (qd->clients[n] == NULL) {
			q = n;
			c->qnum = n;
			qd->clients[n] = c;
			break;
		}
	}
	if (q < 0) {
		pr_err("no available queue for the client\n");
		ret = -ENOSPC;
		goto out;
	}

	pr_info("assign a new client to q %d\n", c->qnum);

	ret = restart_port(qd);

out:
	if (c)
		send_reply(fd, ret, q);

	if (ret < 0) /* failed to register. release the client */
		free(c);
}

static void handle_unregister(struct qdispatcher *qd, int fd,
			      struct msg_hdr *hdr)
{
	struct msg_unregister *unreg = (struct msg_unregister *)hdr;
	struct client *remove = NULL;
	int n, ret = 0;

	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (c && c->qnum == unreg->qnum) {
			remove = c;
			break;
		}
	}

	if (!remove) {
		pr_err("no client for qnum %d\n", unreg->qnum);
		ret = -ENOENT;
		pr_info("ret %d\n", ret);
		goto reply_out;
	}

	pr_info("unregister queue %d\n", remove->qnum);

	qd->clients[remove->qnum] = NULL;
	ret = restart_port(qd);

reply_out:
	send_reply(fd, ret, unreg->qnum);

	if (ret == 0) { /* success  */
		close(remove->fd);
		free(remove);
	}

	close(fd);
}

static int dispatch_loop(struct qdispatcher *qd)
{
	struct sockaddr_un sun;
	struct msg_hdr *hdr;
	socklen_t sunlen;
	char buf[1024];
	int ret;

	pr_info("start qdispatcher for port %d\n", qd->portid);

	listen(qd->fd, 10);

	while (1) {
		int fd;

		sunlen = sizeof(sun);
		fd = accept(qd->fd, (struct sockaddr *)&sun, &sunlen);
		if (fd < 0) {
			pr_err("accept failed: %s\n", strerror(errno));
			continue;
		}

		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			pr_err("read failed: %s\n", strerror(errno));
			close(fd);
			continue;
		}

		hdr = (struct msg_hdr *)buf;

		pthread_mutex_lock(&qd->clients_lock);

		switch (hdr->type) {
		case QDISPATCHER_MSG_TYPE_REGISTER:
			if (ret < sizeof(struct msg_register)) {
				pr_err("invalid msg length for register\n");
				continue;
			}
			handle_register(qd, fd, hdr);
			break;
		case QDISPATCHER_MSG_TYPE_UNREGISTER:
			if (ret < sizeof(struct msg_unregister)) {
				pr_err("invalid msg length for unregister\n");
				continue;
			}
			handle_unregister(qd, fd, hdr);
			break;
		default:
			pr_err("invalid hdr type %d\n", hdr->type);
			break;
		}

		pthread_mutex_unlock(&qd->clients_lock);
	}

	return 0;
}

/* transferring broadcast/multicast frams via sockets */
static void send_bm_frame(struct rte_mbuf *pkt, struct client *c)
{
	struct iovec iov[pkt->nb_segs + 1]; /* 0 is msg_frame */
	struct msg_frame frame;
	struct rte_mbuf *m;
	int n, ret;

	frame.hdr.type = QDISPATCHER_MSG_TYPE_FRAME;
	iov[0].iov_base = &frame;
	iov[0].iov_len = sizeof(frame);

	m = pkt;
	for (n = 0; n < pkt->nb_segs; n++) {
		iov[n + 1].iov_base = rte_pktmbuf_mtod(m, void *);
		iov[n + 1].iov_len = m->data_len;
		m = m->next;
	}

	ret = writev(c->fd, iov, pkt->nb_segs + 1);
	if (ret < 0) {
		pr_err("failed to send packet to client: %s\n",
		       strerror(errno));
	}
}

#define BURST 16
static void *handle_bm_thread(void *arg)
{
	struct qdispatcher *qd = arg;
	struct rte_mbuf *pkts[BURST];
	int n, i, nb_rx;

	do {
		nb_rx = rte_eth_rx_burst(qd->portid, 0, pkts, BURST);
		if (nb_rx == 0) {
			usleep(100);
			continue;
		}

		pthread_mutex_lock(&qd->clients_lock);
		for (n = 0; n < nb_rx; n++) {
			pr_debug("send %d-byte bm frame to client(s)\n",
				 pkts[n]->pkt_len);
			for (i = 1; i < qd->nqueues; i++) {
				struct client *c = qd->clients[i];
				if (!c)
					continue;
				send_bm_frame(pkts[n], c);
			}
		}
		pthread_mutex_unlock(&qd->clients_lock);

		for (n = 0; n < nb_rx; n++)
			rte_pktmbuf_free(pkts[n]);

	} while (1);

	return NULL;
}


static int init_unix_sock(void)
{
	struct sockaddr_un sun;
	int fd;

	unlink(QDISPATCHER_SOCK_PATH); /* XXX: terrible work */

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pr_err("failed to create unix domain socket: %s\n",
		       strerror(errno));
		return -1;
	}

	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, QDISPATCHER_SOCK_PATH, sizeof(sun.sun_path));

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		pr_err("failed to bind unix domain socket: %s\n",
		       strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void usage(void)
{
	printf("usage: dpdk-qdispatcher\n"
	       "    -p PORT    dpdk port id\n"
	       "    -n NUM     max number of queues and clients\n"
	       "    -d         enable debug pring\n"
	       "\n");
}

int main(int argc, char **argv)
{
	int ret, opt;
	pthread_t tid;
	struct option lgopts[] = {
		{ "port", required_argument, NULL, 'p' },
		{ "num", required_argument, NULL, 'n' },
		{ "debug", no_argument, NULL, 'd' },
		{ NULL, 0, 0, 0 },
	};

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "cannot init EAL\n");

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		rte_exit(EXIT_FAILURE,
			 "qdispatcher must be the primary processs\n");

	/* initialize qdispatcher */
	memset(&qd, 0, sizeof(qd));
	qd.portid = 0;
	qd.nqueues = 16;
	pthread_mutex_init(&qd.clients_lock, NULL);

	argc -=ret;
	argv += ret;

	while ((opt = getopt_long(argc, argv, "p:n:dh", lgopts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			qd.portid = atoi(optarg);
			break;
		case 'n':
			qd.nqueues = atoi(optarg);
			break;
		case 'd':
			debug++;
			break;
		case 'h':
		default:
			usage();
			return -1;
		}
	}

	qd.default_rx_pool = rte_pktmbuf_pool_create("default-rx-pool",
						     512 * qd.nqueues,
						     0, 0,
						     RTE_MBUF_DEFAULT_BUF_SIZE,
						     rte_socket_id());
	if (!qd.default_rx_pool) {
		pr_err("failed to allocate default rx mbuf pool: %s\n",
		       rte_strerror(rte_errno));
		return -1;
	}

	/* init server socket */
	qd.fd = init_unix_sock();
	if (qd.fd < 0)
		return -1;

	/* prepare port conf */
	ret = rte_eth_dev_info_get(qd.portid, &qd.info);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			 "failed to get dev_info for port %d: %s\n",
			 qd.portid, rte_strerror(rte_errno));
	}

	/* XXX */
	qd.conf.txmode.offloads = qd.info.tx_offload_capa;
	qd.conf.rxmode.offloads = (DEV_RX_OFFLOAD_CHECKSUM |
				   DEV_RX_OFFLOAD_TCP_LRO |
				   DEV_RX_OFFLOAD_SCATTER); /* XXX: LRO only */
	qd.conf.rxmode.max_lro_pkt_size = qd.info.max_lro_pkt_size;

	qd.conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	qd.conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

	/* prepare array for pointers of struct clinet */
	qd.clients = calloc(qd.nqueues, sizeof(struct client *));
	if (!qd.clients)
		rte_exit(EXIT_FAILURE, "failed to alloc client array\n");
	memset(qd.clients, 0, qd.nqueues * sizeof(struct client *));

	pr_info("we can accomodate %d clients\n", qd.nqueues);

	/* start port before start handle_bm_thread */
	restart_port(&qd);

	/* start handle_bm_thread on queue 0 */
	ret = pthread_create(&tid, NULL, handle_bm_thread, &qd);
	if (ret < 0) {
		pr_err("failed to spawn handle_bm_thread: %s\n",
		       strerror(errno));
		return ret;
	}

	return dispatch_loop(&qd);
}
