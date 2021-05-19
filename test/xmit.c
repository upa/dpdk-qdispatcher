#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_debug.h>

#include <qdc.h>
#include <util.h>

struct rte_mempool *rx_mp, *tx_mp;
struct rte_ether_addr mac;

qdc_t *try_register(int procn)
{
	struct rte_eth_dev_info info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	char mp_name[RTE_MEMZONE_NAMESIZE];
	qdc_t *qdc;
	int ret;

	ret = rte_eth_dev_info_get(0, &info);
	if (ret < 0) {
		pr_err("failed to get dev info of port 0\n");
		return NULL;
	}

	txconf = info.default_txconf;
	rxconf = info.default_rxconf;
	mac.addr_bytes[0] = 0x02;
	mac.addr_bytes[1] = 0x00;
	mac.addr_bytes[2] = 0x00;
	mac.addr_bytes[3] = 0x00;
	mac.addr_bytes[4] = 0x00;
	mac.addr_bytes[5] = procn;

	snprintf(mp_name, sizeof(mp_name), "rx-pool-%d", procn);
	rx_mp = rte_pktmbuf_pool_create(mp_name, 1024, 0, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id());
	if (!rx_mp) {
		pr_err("failed to allocate rx mbuf pool: %s\n",
		       rte_strerror(rte_errno));
		return NULL;
	}

	qdc = qdc_register(rx_mp, 512, 512, txconf, rxconf, mac);
	if (!qdc) {
		rte_mempool_free(rx_mp);
		rx_mp = NULL;
		return NULL;
	}

	pr_info("queue %d registered\n", qdc_qnum(qdc));

	return qdc;
}

int try_unregister(qdc_t *qdc)
{
	return qdc_unregister(qdc);
}



struct param {
	int procn;
	int loop_count;
} p;

#define BURST	8

int xmit_one_iter(int qnum, struct rte_mempool *tx_mp)
{
	struct rte_mbuf *pkts[BURST];
	struct rte_ether_hdr *eth;
	int ret, n;

	ret = rte_pktmbuf_alloc_bulk(tx_mp, pkts, BURST);
	if (ret < 0) {
		pr_err("failed to alloc pkts\n");
		return ret;
	}

	for (n = 0; n < BURST; n++) {
		eth = (struct rte_ether_hdr *)rte_pktmbuf_append(pkts[n], 128);
		memset(&eth->d_addr, 0xFF, RTE_ETHER_ADDR_LEN);
		memcpy(&eth->s_addr, &mac, RTE_ETHER_ADDR_LEN);
		eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	}

	return rte_eth_tx_burst(0, qnum, pkts, BURST);
}


int xmit(int qnum)
{
	char mp_name[RTE_MEMZONE_NAMESIZE];
	int ret, n;

	snprintf(mp_name, sizeof(mp_name), "tx-pool-%d\n", p.procn);
	tx_mp = rte_pktmbuf_pool_create(mp_name, 1024, 0, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id());
	if (!tx_mp) {
		pr_err("failed to allocate tx mbuf pool: %s\n",
		       rte_strerror(rte_errno));
		return -ENOMEM;
	}

	for (n = 0; n < p.loop_count; n++) {
		ret = xmit_one_iter(qnum, tx_mp);
		pr_info("xmit %d pkts done, sleep 1 sec\n", ret);
		sleep(1);
	}

	return 0;
}

void usage(void)
{
	printf("usage: test-xmit -n [PROCESS_NUMBER] -c [LOOP_COUNT]\n");
}

int main(int argc, char **argv)
{
	int ret, ch;
	qdc_t *qdc;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("cannot init EAL\n");

	p.procn = 0;
	p.loop_count = 1;

	argc--;
	argv++;

	while ((ch = getopt(argc, argv, "n:c:h")) != -1) {
		switch (ch) {
		case 'n':
			p.procn = atoi(optarg);
			break;
		case 'c':
			p.loop_count = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
			return -1;
		}
	}

	printf("process number %d\n", p.procn);

	qdc = try_register(p.procn);
	if (!qdc) {
		pr_err("register failed\n");
		return -1;
	}

	pr_info("our queue number is %d\n", qdc_qnum(qdc));

	xmit(qdc_qnum(qdc));

	ret = try_unregister(qdc);
	if (ret != 0) {
		pr_err("unregister failed: %s\n", strerror(ret * -1));
		return ret;
	}

	pr_info("unregister done\n");

	if (rx_mp)
		rte_mempool_free(rx_mp);
	if (tx_mp)
		rte_mempool_free(tx_mp);

	return ret;
}

