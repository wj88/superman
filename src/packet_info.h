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
	struct sk_buff *skb;
	const struct nf_hook_state *state;

	// Useful pointers to the relevant parts of the packet.
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;

	// Address information about the origin/destination of this packet.
	__be32 ifaddr;
	__be32 bcaddr;
	int addr_type;

	// Security information

	// End to end
	__be32 e2e_addr;		// The address of the other end (destination or source)
	bool e2e_secure_packet;
	bool e2e_use_broadcast_key;
	struct security_table_entry* e2e_security_details;
	bool e2e_has_security_details;

	// Point to point
	__be32 p2p_our_addr;
	__be32 p2p_neighbour_addr;
	bool p2p_secure_packet;
	bool p2p_use_broadcast_key;
	struct security_table_entry* p2p_security_details;
	bool p2p_has_security_details;

	// The result (one of the NF_* values)
	unsigned int result;
	bool use_callback;

	// Temporary storage locations for use by any phase of the process as appropriate.
	void* arg;
	void* tmp;

	// Queue support
	__be32 queue_addr;
	struct timeval queue_entry_time;
	

	// Temporary spi identifier
	uint32_t id;
};

//uint16_t GetNextTimestampFromSupermanPacketInfo(struct superman_packet_info* spi);
struct superman_packet_info* MallocSupermanPacketInfo(struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int FreeSupermanPacketInfo(struct superman_packet_info* spi);

#endif

#endif
