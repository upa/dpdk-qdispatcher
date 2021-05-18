#ifndef _QDISPATCHER_H_
#define _QDISPATCHER_H_

#include <rte_ethdev.h>

#define QDISPATCHER_RING_NAME	"CLIENT_TO_QDISPATCHER"
#define QDISPATCHER_MP_NAME	"QDISPATCHER_MEMPOOL"

enum {
	QDISPATCHER_MSG_TYPE_JOIN,
	QDISPATCHER_MSG_TYPE_REPLY,
	QDISPATCHER_MSG_TYPE_LEAVE,
};


struct qdispatcher_hdr {
	int type;
};

struct qdispatcher_join {
	struct qdispatcher_hdr hdr;
	char	rx_mp_name[RTE_MEMZONE_NAMESIZE];
	char	ring_name[RTE_MEMZONE_NAMESIZE];
	char	mac[6];

	int	nb_txd, nb_rxd;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
};

struct qdispatcher_leave { 
	struct qdispatcher_hdr hdr;
	int	qnum;
};

struct qdispatcher_join_reply {
	struct qdispatcher_hdr hdr;
	int	ret;
	int	err;
	int	qnum;
};

/* err code */
enum {
	QDISPATCHER_ERR_NONE,

	/* join */
	QDISPATCHER_ERR_NO_AVAILABLE_QUEUE,

	/* leave */
	QDISPATCHER_ERR_NO_REGISTERED_QUEUE_NUM,
};


#endif /* _QDISPATCHER_H_ */
