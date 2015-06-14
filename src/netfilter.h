#ifndef __SUPERMAN_NETFILTER__
#define __SUPERMAN_NETFILTER__

#ifdef __KERNEL__

#include <linux/skbuff.h>

#include "superman.h"

#ifndef NF_IP_PRE_ROUTING
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5
#endif

bool is_valid_packet(struct sk_buff *skb);
bool is_superman_packet(struct sk_buff* skb);
struct superman_header* get_superman_header(struct sk_buff *skb);


void InitNetFilter(void);
void DeInitNetFilter(void);

#endif

#endif
