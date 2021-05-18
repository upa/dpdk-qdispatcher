#ifndef _QDC_H_
#define _QDC_H_

#include <rte_ethdev.h>
#include <rte_mempool.h>

typedef struct qdc qdc_t;

qdc_t *qdc_register(struct rte_mempool *rx_mp,
		    uint16_t nb_txd, uint16_t nb_rxd,
		    struct rte_eth_txconf txconf,
		    struct rte_eth_rxconf rxconf,
		    struct rte_ether_addr mac);


int qdc_unregister(qdc_t *qdc);

int qdc_qnum(qdc_t *qdc);


#endif /* _QDC_H_ */
