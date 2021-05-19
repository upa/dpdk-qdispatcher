#ifndef _QDISPATCHER_H_
#define _QDISPATCHER_H_

#include <rte_ethdev.h>

/* private */

#define QDISPATCHER_RING_NAME	"CLIENT_TO_QDISPATCHER"
#define QDISPATCHER_MP_NAME	"QDISPATCHER_MEMPOOL"

enum {
	QDISPATCHER_MSG_TYPE_REGISTER,
	QDISPATCHER_MSG_TYPE_UNREGISTER,
	QDISPATCHER_MSG_TYPE_REPLY,
 };

struct msg_hdr {
	int type;
};

struct msg_register {
	struct msg_hdr hdr;
	char	rx_mp_name[RTE_MEMZONE_NAMESIZE];
	char	ring_name[RTE_MEMZONE_NAMESIZE];

	uint16_t	nb_txd, nb_rxd;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_ether_addr mac;
};

struct msg_unregister {
	struct msg_hdr hdr;
	int	qnum;
};

struct msg_reply {
	struct msg_hdr hdr;
	int	ret;
	int	qnum;
};

/* err code */
enum {
	QDERR_NONE = 0,

	/* join */
	QDERR_NO_QUEUE,
	QDERR_NO_MEMORY,
	QDERR_NO_RXMEMPOOL,
	QDERR_NO_RING,
	QDERR_NO_MEMSPACE,
	QDERR_NO_RINGSPACE,
	QDERR_TIMEOUT,

	/* leave */
	QDERR_NO_REGISTERED_QUEUE,

	QDERR_MAX,
};


#endif /* _QDISPATCHER_H_ */
