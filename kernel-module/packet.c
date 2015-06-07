#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/route.h>
#include <net/ip.h>

#include "packet.h"

static inline u_int8_t _encode_ip_protocol(u_int8_t protocol)
{
	return protocol + SUPERMAN_MAX_TYPE;
}

static inline u_int8_t _decode_ip_protocol(u_int8_t superman_protocol)
{
	return superman_protocol - SUPERMAN_MAX_TYPE;
}

void SendDiscoveryRequest(void)
{
	struct net_device *dev;
	printk(KERN_INFO "SUPERMAN: Discovery Request...\n");

	printk(KERN_INFO "\tSUPERMAN: Locking dev_base\n");
	read_lock(&dev_base_lock);

	printk(KERN_INFO "\tSUPERMAN: Iterating netdev's\n");
	for_each_netdev(&init_net, dev) {

		struct sk_buff* tx_sk;
		struct superman_header* shdr;
		struct iphdr* iph;
		struct flowi4 fl;
		struct rtable* rt;
		struct dst_entry *dst;

		// Allocate a new packet
		tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header), GFP_KERNEL);
		tx_sk->dev = dev;
		tx_sk->pkt_type = PACKET_OUTGOING | PACKET_BROADCAST;				// Its outgoing.
		tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

		// Reserve space for the IP and SUPERMAN headers
		skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

		// Payload would normally go here, but we don't have any.
		//unsigned char* payload = skb_put(skb, data_size);
		//memcpy(payload, data, data_size);

		// Setup the superman header
		shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
		skb_reset_transport_header(tx_sk);
		shdr->type = SUPERMAN_DISCOVERY_REQUEST_TYPE;					// We're preparing a discovery request packet.
		shdr->timestamp = ntohs(0);							// This will be a unique counter value for each packet, cycling round.
		shdr->payload_len = 0;								// A discovery request has no payload.

		// Setup the IP header
		iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
		skb_reset_network_header(tx_sk);
		iph->version = 4;								// IPv4 only, for now.
		iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
		iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
;		iph->tot_len = htons(tx_sk->len);						// Total length of the packet
		iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
		iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
		iph->ttl = 64;									// A recommended value (in seconds)
		iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
		iph->check = 0;									// No checksum yet
		iph->saddr = inet_select_addr(dev, htonl(INADDR_BROADCAST), RT_SCOPE_UNIVERSE);	// Grab the most appropriate address.
		//iph->daddr = ((iph->saddr & 0x00FFFFFF) + 0xFF000000),			// Broadcast the message to all on the subnet
		iph->daddr = htonl(INADDR_BROADCAST);						// Broadcast the message to all on the subnet
		ip_send_check(iph);
		
		flowi4_init_output(&fl, dev->ifindex, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, iph->daddr, iph->saddr, 0, 0);
		rt = ip_route_output_key(dev_net(dev), &fl);
		if(IS_ERR(rt))
			printk(KERN_INFO "\tSUPERMAN: Routing failed.\n");
		else
		{
			skb_dst_set(tx_sk, &rt->dst);
			dst = skb_dst(tx_sk);
			printk(KERN_INFO "\tSUPERMAN: Sending packet\n");
			tx_sk->dev = dst->dev;
			dst->output(tx_sk);
		}
	}

	printk(KERN_INFO "\tSUPERMAN: Unlocking dev_base\n");
	read_unlock(&dev_base_lock);

	printk(KERN_INFO "SUPERMAN: ... Discovery Request done.\n");
}

void SendIncomingPrerouted(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{
	struct net_device *dev;
	struct sk_buff* tx_sk;
	struct iphdr* iph;
	struct dst_entry *dst;
	void* data;

	printk(KERN_INFO "SUPERMAN: Sending incoming prerouted packet...\n");

	// Grab the device from the incoming packet.
	dev = dev_get_by_index(&init_net, ifindex);

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + payload_len, GFP_KERNEL);
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_INCOMING;							// Its incoming.
	tx_sk->ip_summed = CHECKSUM_NONE;							// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr));

	// Payload goes here.
	data = skb_put(tx_sk, payload_len);
	memcpy(data, payload, payload_len);

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;									// IPv4 only, for now.
	iph->ihl = 5;										// Number of 32-bit words in the header (min 5)
	iph->tos = 0;										// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);							// Total length of the packet
	iph->frag_off = htons(0);								// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);									// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;										// A recommended value (in seconds)
	iph->protocol = protocol;								// Provide the protocol number
	iph->check = 0;										// No checksum yet
	iph->saddr = src_addr;									// Provide the source IP
	iph->daddr = dst_addr;									// Provide the desintation IP
	ip_send_check(iph);

	if(IS_ERR(ip_route_input(tx_sk, iph->daddr, iph->saddr, iph->tos, dev)))
		printk(KERN_INFO "\tSUPERMAN: Routing failed.\n");
	else
	{
		dst = skb_dst(tx_sk);
		printk(KERN_INFO "\tSUPERMAN: Sending packet\n");
		ip_rcv_finish(tx_sk);
	}

	printk(KERN_INFO "SUPERMAN: ... Incoming prerouted packet sent.\n");
}

void SendIncomingPostrouted(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{
	struct net_device *dev;
	struct sk_buff* tx_sk;
	struct iphdr* iph;
	struct dst_entry *dst;
	void* data;

	printk(KERN_INFO "SUPERMAN: Sending incoming prerouted packet...\n");

	// Grab the device from the incoming packet.
	dev = dev_get_by_index(&init_net, ifindex);

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + payload_len, GFP_KERNEL);
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_INCOMING;							// Its incoming.
	tx_sk->ip_summed = CHECKSUM_NONE;							// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr));

	// Payload goes here.
	data = skb_put(tx_sk, payload_len);
	memcpy(data, payload, payload_len);

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;									// IPv4 only, for now.
	iph->ihl = 5;										// Number of 32-bit words in the header (min 5)
	iph->tos = 0;										// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);							// Total length of the packet
	iph->frag_off = htons(0);								// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);									// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;										// A recommended value (in seconds)
	iph->protocol = protocol;								// Provide the protocol number
	iph->check = 0;										// No checksum yet
	iph->saddr = src_addr;									// Provide the source IP
	iph->daddr = dst_addr;									// Provide the desintation IP
	ip_send_check(iph);

	if(IS_ERR(ip_route_input(tx_sk, iph->daddr, iph->saddr, iph->tos, dev)))
		printk(KERN_INFO "\tSUPERMAN: Routing failed.\n");
	else
	{
		dst = skb_dst(tx_sk);
		printk(KERN_INFO "\tSUPERMAN: Sending packet\n");
		ip_local_deliver(tx_sk);
	}

	printk(KERN_INFO "SUPERMAN: ... Incoming prerouted packet sent.\n");
}

void SendOutgoingPrerouted(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{
	struct net_device *dev;
	struct sk_buff* tx_sk;
	struct iphdr* iph;
	struct flowi4 fl;
	struct rtable* rt;
	struct dst_entry *dst;
	void* data;

	printk(KERN_INFO "SUPERMAN: Sending incoming prerouted packet...\n");

	// Grab the device from the incoming packet.
	dev = dev_get_by_index(&init_net, ifindex);

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + payload_len, GFP_KERNEL);
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_INCOMING;							// Its incoming.
	tx_sk->ip_summed = CHECKSUM_NONE;							// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr));

	// Payload goes here.
	data = skb_put(tx_sk, payload_len);
	memcpy(data, payload, payload_len);

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;									// IPv4 only, for now.
	iph->ihl = 5;										// Number of 32-bit words in the header (min 5)
	iph->tos = 0;										// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);							// Total length of the packet
	iph->frag_off = htons(0);								// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);									// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;										// A recommended value (in seconds)
	iph->protocol = protocol;								// Provide the protocol number
	iph->check = 0;										// No checksum yet
	iph->saddr = src_addr;									// Provide the source IP
	iph->daddr = dst_addr;									// Provide the desintation IP
	ip_send_check(iph);

	flowi4_init_output(&fl, dev->ifindex, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, iph->daddr, iph->saddr, 0, 0);
	rt = ip_route_output_key(dev_net(dev), &fl);
	if(IS_ERR(rt))
		printk(KERN_INFO "\tSUPERMAN: Routing failed.\n");
	else
	{
		skb_dst_set(tx_sk, &rt->dst);
		dst = skb_dst(tx_sk);
		printk(KERN_INFO "\tSUPERMAN: Sending packet\n");
		tx_sk->dev = dst->dev;
		dst->output(tx_sk);
	}

	printk(KERN_INFO "SUPERMAN: ... Incoming prerouted packet sent.\n");
}

void SendOutgoingPostrouted(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{
	struct net_device *dev;
	struct sk_buff* tx_sk;
	struct iphdr* iph;
	struct flowi4 fl;
	struct rtable* rt;
	struct dst_entry *dst;
	void* data;

	printk(KERN_INFO "SUPERMAN: Sending incoming prerouted packet...\n");

	// Grab the device from the incoming packet.
	dev = dev_get_by_index(&init_net, ifindex);

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + payload_len, GFP_KERNEL);
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_INCOMING;							// Its incoming.
	tx_sk->ip_summed = CHECKSUM_NONE;							// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr));

	// Payload goes here.
	data = skb_put(tx_sk, payload_len);
	memcpy(data, payload, payload_len);

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;									// IPv4 only, for now.
	iph->ihl = 5;										// Number of 32-bit words in the header (min 5)
	iph->tos = 0;										// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);							// Total length of the packet
	iph->frag_off = htons(0);								// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);									// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;										// A recommended value (in seconds)
	iph->protocol = protocol;								// Provide the protocol number
	iph->check = 0;										// No checksum yet
	iph->saddr = src_addr;									// Provide the source IP
	iph->daddr = dst_addr;									// Provide the desintation IP
	ip_send_check(iph);

	flowi4_init_output(&fl, dev->ifindex, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, iph->daddr, iph->saddr, 0, 0);
	rt = ip_route_output_key(dev_net(dev), &fl);
	if(IS_ERR(rt))
		printk(KERN_INFO "\tSUPERMAN: Routing failed.\n");
	else
	{
		skb_dst_set(tx_sk, &rt->dst);
		dst = skb_dst(tx_sk);
		printk(KERN_INFO "\tSUPERMAN: Sending packet\n");
		tx_sk->dev = dst->dev;
		dst->output(tx_sk);
	}

	printk(KERN_INFO "SUPERMAN: ... Incoming prerouted packet sent.\n");
}

