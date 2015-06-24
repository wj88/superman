#ifndef __SUPERMAN_SUPERMAN_PACKET_INFO_H
#define __SUPERMAN_SUPERMAN_PACKET_INFO_H

#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#include "security_table.h"

#define IS_OTHER	0
#define IS_MYADDR       1               // address is (one of) our own
#define IS_LOOPBACK     2               // address is for LOOPBACK
#define IS_BROADCAST    3               // address is a valid broadcast
#define IS_INVBCAST     4               // Wrong netmask bcast not for us (unused)
#define IS_MULTICAST    5               // Multicast IP address

// The superman_packet_info, or SPI, is used to keep track of useful information about a packet
// as it propergates through the kernel processing elements of SUPERMAN.
struct superman_packet_info
{
	// A list_head reference because this SPI can be stored within a queue.
	struct list_head list;

	// Information provided by the hook function where the SPI originated.
	unsigned int hooknum;
	struct sk_buff *skb;
	const struct net_device *in;
	const struct net_device *out;
	int (*okfn)(struct sk_buff *);

	// Useful pointers to the relevant parts of the packet.
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;

	// Address information about the origin/destination of this packet.
	struct in_addr ifaddr;
	struct in_addr bcaddr;
	__be32 addr;
	int addr_type;

	// Security information
	bool secure_packet;
	bool use_broadcast_key;
	int security_flag;
	struct security_table_entry* security_details;
	bool has_security_details;

	// The result (one of the NF_* values)
	unsigned int result;
	bool use_callback;

	// Temporary storage locations for use by any phase of the process as appropriate.
	void* arg;
	void* tmp;
};

struct superman_packet_info* MallocSupermanPacketInfo(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int FreeSupermanPacketInfo(struct superman_packet_info* spi);

#endif

#endif
