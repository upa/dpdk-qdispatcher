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
#include <qdc.h>
#include <util.h>

static void random_text(char *txt, size_t size)
{
	int n;
	char chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	for (n = 0; n < size - 1; n++) {
		txt[n] = chars[rand() & sizeof(chars)];
	}
	txt[n] = '\0';
}

struct qdc {
	struct rte_ring *c_ring;	/* my (client) ring */
	struct rte_ring *d_ring;	/* dispatcher's ring */
	struct rte_mempool *d_mp;	/* dispatcher's mempool */
	struct msg_register reg;
	int qnum;
};

static int do_register(qdc_t *qdc, int *qnum)
{
	int timeout = 1000 * 1000;	/* 1sec */
	struct msg_reply *rep;
	void *msg;
	int ret;

	/* send register message */
	if (rte_mempool_get(qdc->d_mp, &msg) < 0) {
		pr_err("no available message in the pool\n");
		return QDERR_NO_MEMSPACE;
	}

	memcpy(msg, &qdc->reg, sizeof(qdc->reg));
	if (rte_ring_enqueue(qdc->d_ring, msg) < 0) {
		pr_err("failed to put register msg to the ring\n");
		return QDERR_NO_RINGSPACE;
	}

	/* wait reply */
	while (rte_ring_dequeue(qdc->c_ring, &msg) < 0) {
		usleep(10);
		timeout -= 10;
		if (timeout < 0) {
			pr_err("timed out\n");
			return QDERR_TIMEOUT;
		}
	}

	rep = msg;
	if (rep->ret == 0)
		*qnum = rep->qnum;
	ret = rep->err; /* QDERR_NONE (0) is ok */

	rte_mempool_put(qdc->d_mp, msg);

	return ret;
}

static const char *qd_ring_name = QDISPATCHER_RING_NAME;
static const char *qd_mp_name = QDISPATCHER_MP_NAME;

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

	/* create client ring */
	random_text(qdc->reg.ring_name, RTE_MEMZONE_NAMESIZE);
	qdc->c_ring = rte_ring_create(qdc->reg.ring_name, 32,
				      rte_socket_id(), 0);
	if (!qdc->c_ring) {
		pr_err("failed to create ring: %s\n", rte_strerror(rte_errno));
		goto free_out;
	}

	qdc->d_ring = rte_ring_lookup(qd_ring_name);
	if (!qdc->d_ring) {
		pr_err("ring %s not found\n", qd_ring_name);
		goto free_out;
	}

	qdc->d_mp = rte_mempool_lookup(qd_mp_name);
	if (!qdc->d_mp) {
		pr_err("mempool %s not found\n", qd_mp_name);
		goto free_out;
	}

	/* try register */
	ret = do_register(qdc, &qdc->qnum);
	if (ret != 0) {
		pr_err("registration failed: err %d\n", ret);
		goto free_out;
	}

	return qdc;

free_out:
	free(qdc);
	return NULL;
}


int qdc_unregister(qdc_t *qdc)
{
	return 0;
}


int qdc_qnum(qdc_t *qdc)
{
	return qdc->qnum;
}
