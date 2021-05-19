#ifndef _QDISPATCHER_H_
#define _QDISPATCHER_H_

#include <string.h>

#include <rte_ethdev.h>

/* private */

#define QDISPATCHER_SOCK_PATH "/tmp/qdispatcher.sock"


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



#endif /* _QDISPATCHER_H_ */
