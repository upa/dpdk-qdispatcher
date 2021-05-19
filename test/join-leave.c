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

struct rte_mempool *mp;

qdc_t *try_register(int procn)
{
	struct rte_eth_dev_info info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_ether_addr mac;
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
	mac.addr_bytes[5] = 0x00;

	snprintf(mp_name, sizeof(mp_name), "rx-pool-%d", procn);
	mp = rte_pktmbuf_pool_create(mp_name, 1024, 0, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE,
				     rte_socket_id());
	if (!mp) {
		pr_err("failed to allocate rx mbuf pool\n");
		return NULL;
	}

	qdc = qdc_register(mp, 512, 512, txconf, rxconf, mac);
	if (!qdc) {
		rte_mempool_free(mp);
		return NULL;
	}

	pr_info("queue %d registered\n", qdc_qnum(qdc));

	return qdc;
}

int try_unregister(qdc_t *qdc)
{
	return qdc_unregister(qdc);
}

void usage(void)
{
	printf("usage: test-join-leave -n [PROCESS_NUMBER]\n");
}

int main(int argc, char **argv)
{
	int ret, ch;
	qdc_t *qdc;
	int procn = 0;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("cannot init EAL\n");

	argc--;
	argv++;

	while ((ch = getopt(argc, argv, "n:h")) != -1) {
		switch (ch) {
		case 'n':
			procn = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
			return -1;
		}
	}

	printf("process number %d\n", procn);

	qdc = try_register(procn);
	if (!qdc) {
		pr_err("register failed\n");
		return -1;
	}

	pr_info("our queue number is %d\n", qdc_qnum(qdc));

	printf("type Enter to unregister\n");
	char buf[32];
	fgets(buf, sizeof(buf), stdin);

	ret = try_unregister(qdc);
	if (ret != 0) {
		pr_err("unregister failed: %s\n", strerror(ret * -1));
		return ret;
	}

	pr_info("unregister done\n");

	rte_mempool_free(mp);

	return ret;
}

