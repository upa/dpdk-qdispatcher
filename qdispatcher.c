#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_debug.h>

#include <qdispatcher.h>

#define pr_info(fmt, ...) fprintf(stdout, "INFO:%s(): " fmt,	\
				  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"     \
				  "WARN:%s(): " fmt "\x1b[0m",  \
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[31m"      \
				 "ERR:%s(): " fmt "\x1b[0m",    \
				 __func__, ##__VA_ARGS__)

#define min(a, b) (a > b) ? b : a
#define max(a, b) (a > b) ? a : b

/* structure describing client process */
struct client {
	int qnum;	/* queue number for the client */
	struct rte_mempool *rx_mp;	/* rx mempool in the client */

	struct rte_ether_addr mac;	/* mac addr of this client */
	/* packets to this mac are sent to the associate queue by
	 * rte_flow. broadcast and multicast frames are copied to the
	 * all queues. */

	struct rte_ring	*ring;	/* ring to send reply to the client */

	/* params for configuring queue */
	int nb_txd, nb_rxd;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
};

/* structure describing qdispatcher process */
struct qdispatcher {
	int portid;	/* physical port id. XXX: now always 0  */
	struct rte_eth_conf 	conf;
	struct rte_eth_dev_info	info;

	struct rte_ring	*ring;	/* ring to recv msg from clients */
	struct rte_mempool *mp; /* mp for messages over rings.  all
				 * clients and qdispatcher allocates
				 * message from this mp.
				 */

	int nqueues;
	struct client **clients;	/* number of nqueues array of
					 * struct client
					 * pointers. each index
					 * indicates a queue number
					 * for the client.
					 */
};

static struct qdispatcher qd;



/**** restart the port ****/
void restart_port(struct qdispatcher *qd)
{
	int ret, n, max_qnum = -1;
	uint16_t max_txd = 512, max_rxd = 512;

	/* stop, configure, queue stup, and start*/

	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (c) {
			max_qnum = max(max_qnum, c->qnum);
			max_txd = max(max_txd, c->nb_txd);
			max_rxd = max(max_rxd, c->nb_rxd);
		}
	}
	if (max_qnum < 0) {
		pr_err("no runnable queues\n");
		return;
	}
	max_qnum++; /* queue number + 1 means number of queues */

	/* stop */
	ret = rte_eth_dev_stop(qd->portid);
	if (ret < 0) {
		pr_err("failed to stop port %d\n", qd->portid);
		return;
	}

	/* configure port */
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(qd->portid, &max_txd, &max_rxd);
	if (ret < 0) {
		pr_err("failed to configure port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
		return;
	}

	ret = rte_eth_dev_configure(qd->portid, max_qnum, max_qnum, &qd->conf);
	if (ret < 0) {
		pr_err("failed to configure port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
		return;
	}

	/* configure queues */
	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (!c)
			continue;

		pr_info("configure quene %d\n", n);
		ret = rte_eth_tx_queue_setup(qd->portid, n, c->nb_txd,
					     SOCKET_ID_ANY, &c->txconf);
		if (ret < 0) {
			pr_err("failed to configure tx q %d: %s\n",
			       n, rte_strerror(rte_errno));
		}

		ret = rte_eth_rx_queue_setup(qd->portid, n, c->nb_rxd,
					     SOCKET_ID_ANY, &c->rxconf,
					     c->rx_mp);
		if (ret < 0) {
			pr_err("failed to configure rx q %d: %s\n",
			       n, rte_strerror(rte_errno));
		}
	}

	/* XXX: configure rte_flow for mac per queue here */

	/* start */
	ret = rte_eth_dev_start(qd->portid);
	if (ret < 0) {
		pr_err("failed to start port %d: %s\n",
		       qd->portid, rte_strerror(rte_errno));
	}

	pr_info("restart port %d done\n", qd->portid);
}

/**** handle register ****/

struct client *create_client_from_register(struct msg_register *reg)
{
	struct client *c;

	c = malloc(sizeof(*c));
	if (!c) {
		pr_err("failed to alloc memory for client: %s\n",
		       strerror(errno));
		return NULL;
	}

	memset(c, 0, sizeof(*c));
	c->rx_mp = rte_mempool_lookup(reg->rx_mp_name);
	if (!c->rx_mp) {
		pr_err("rx_mp_name %s not found\n", reg->rx_mp_name);
		goto free_out;
	}

	c->ring = rte_ring_lookup(reg->ring_name);
	if (!c->ring) {
		pr_err("ring_name %s not found\n", reg->ring_name);
		goto free_out;
	}

	memcpy(&c->mac, reg->mac, RTE_ETHER_ADDR_LEN);

	c->nb_txd = reg->nb_txd;
	c->nb_rxd = reg->nb_rxd;
	c->txconf = reg->txconf;
	c->rxconf = reg->rxconf;

	return c;

free_out:
	free(c);
	return NULL;
}

void send_reply(struct qdispatcher *qd, struct rte_ring *r,
		int ret, int err, int qnum)
{
	struct msg_reply *rep;
	void *msg;

	if (rte_mempool_get(qd->mp, &msg) < 0) {
		pr_err("no avaliable message in the pool\n");
		return;
	}

	rep = msg;
	rep->hdr.type = QDISPATCHER_MSG_TYPE_REPLY;
	rep->ret = ret;
	rep->err = err;
	rep->qnum = qnum;

	if (rte_ring_enqueue(r, rep) < 0)
		pr_err("failed to put reply to the ring\n");
}

void handle_register(struct qdispatcher *qd, struct msg_register *reg)
{
	struct client *c;
	int n, q, ret = 0, err = QDISPATCHER_ERR_NONE;

	c = create_client_from_register(reg);
	if (!c) {
		pr_err("failed to add client\n");
		goto out;
	}

	/* find an available queue number for this client*/
	for (q = -1, n = 0; n < qd->nqueues; n++) {
		if (qd->clients[n] == NULL) {
			q = n;
			c->qnum = n;
			qd->clients[n] = c;
			break;
		}
	}
	if (q < 0) {
		pr_err("no available queue for the client\n");
		ret = -1;
		err = QDISPATCHER_ERR_NO_AVAILABLE_QUEUE;
		goto reply_out;
	}

	pr_info("assign a new client to q %d\n", c->qnum);

	restart_port(qd);

reply_out:
	send_reply(qd, c->ring, ret, err, q);
out:
	rte_mempool_put(qd->mp, reg);

	if (ret < 0) /* faileed to register. release the client */
		free(c);
}

void handle_unregister(struct qdispatcher *qd, struct msg_unregister *unreg)
{
	struct client *remove = NULL;
	int n, ret = 0, err = QDISPATCHER_ERR_NONE;

	for (n = 0; n < qd->nqueues; n++) {
		struct client *c = qd->clients[n];
		if (c && c->qnum == unreg->qnum) {
			remove = c;
			break;
		}
	}

	if (!remove) {
		pr_err("no client for qnum %d\n", unreg->qnum);
		ret = -1;
		err = QDISPATCHER_ERR_NO_REGISTERED_QUEUE_NUM;
		goto reply_out;
	}

	qd->clients[remove->qnum] = NULL;
	restart_port(qd);

reply_out:
	send_reply(qd, remove->ring, ret, err, unreg->qnum);
	rte_mempool_put(qd->mp, unreg);

	if (ret == 0) /* success  */
		free(remove);
}

int dispatch_loop(struct qdispatcher *qd)
{
	pr_info("start qdispatcher for port %d\n", qd->portid);

	while (1) {
		struct msg_hdr *hdr;
		void *msg;
		if (rte_ring_dequeue(qd->ring, &msg) < 0) {
			usleep(10);
			continue;
		}

		hdr = msg;

		switch (hdr->type) {
		case QDISPATCHER_MSG_TYPE_REGISTER:
			handle_register(qd, (struct msg_register *)hdr);
			break;
		case QDISPATCHER_MSG_TYPE_UNREGISTER:
			handle_unregister(qd, (struct msg_unregister *)hdr);
			break;
		default:
			pr_err("invalid hdr type %d\n", hdr->type);
			break;
		}
	}

	return 0;
}


static const char *qd_ring_name = QDISPATCHER_RING_NAME;
static const char *qd_mp_name = QDISPATCHER_MP_NAME;

int main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "cannot init EAL\n");

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		rte_exit(EXIT_FAILURE,
			 "qdispatcher must be the primary processs\n");

	/* initialize qdispatcher */
	memset(&qd, 0, sizeof(qd));
	qd.portid = 0;	/* XXX: implement qdispater_parse_args() */

	/* initialize a ring on qdispatcher. clients request
	 * register/unregister to the qdispatcher via this ring. So,
	 * multiple processes put messages to the qd.ring, so it
	 * should be RING_F_MP_ */
	qd.ring = rte_ring_create(qd_ring_name, 32, rte_socket_id(),
				  RING_F_MP_HTS_ENQ);
	if (!qd.ring) {
		rte_exit(EXIT_FAILURE, "failed to alloc qd ring: %s\n",
			 rte_strerror(rte_errno));
	}

	/* all messages between qdispather and each client are
	 * obtained from this mempool to simplify releasing the messages. */
	qd.mp = rte_mempool_create(qd_mp_name, 512,
				   sizeof(struct msg_register), 0, 0,
				   NULL, NULL, NULL, NULL,
				   rte_socket_id(), 0);
	if (!qd.mp) {
		rte_exit(EXIT_FAILURE, "failed to alloc mp for ring: %s\n",
			 rte_strerror(rte_errno));
	}

	/* prepare port conf */
	ret = rte_eth_dev_info_get(qd.portid, &qd.info);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			 "failed to get dev_info for port %d: %s\n",
			 qd.portid, rte_strerror(rte_errno));
	}

	/* XXX */
	qd.conf.txmode.offloads = qd.info.tx_offload_capa;
	qd.conf.rxmode.offloads = qd.info.rx_offload_capa;
	qd.conf.rxmode.max_lro_pkt_size = qd.info.max_lro_pkt_size;
	qd.conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	qd.conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

	/* prepare array for pointers of struct clinet */
	qd.nqueues = min(qd.info.max_tx_queues, qd.info.max_rx_queues);
	qd.clients = calloc(qd.nqueues, sizeof(struct client *));
	if (!qd.clients)
		rte_exit(EXIT_FAILURE, "failed to alloc client array\n");
	memset(qd.clients, 0, qd.nqueues * sizeof(struct client *));

	return dispatch_loop(&qd);
}
