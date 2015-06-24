#ifdef __KERNEL__

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

inline bool is_superman_packet(struct sk_buff* skb)
{
	// Does this IPv4 packet contain superman payload?
	return (ip_hdr(skb)->protocol == SUPERMAN_PROTOCOL_NUM);
}

inline struct superman_header* get_superman_header(struct sk_buff *skb)
{
	return (struct superman_header*)skb_transport_header(skb);
}


void SendDiscoveryRequestPacket(uint32_t sk_len, unsigned char* sk)
{
	struct net_device *dev;
	printk(KERN_INFO "SUPERMAN: Packet - Discovery Request...\n");

	printk(KERN_INFO "SUPERMAN: Packet - \tLocking dev_base\n");
	read_lock(&dev_base_lock);

	printk(KERN_INFO "SUPERMAN: Packet - \tIterating netdev's\n");
	for_each_netdev(&init_net, dev) {

		struct sk_buff* tx_sk;
		struct superman_header* shdr;
		struct iphdr* iph;
		struct flowi4 fl;
		struct rtable* rt;
		struct dst_entry *dst;
		void* payload;

		// Allocate a new packet
		tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header), GFP_KERNEL);
		tx_sk->dev = dev;
		tx_sk->pkt_type = PACKET_OUTGOING | PACKET_BROADCAST;				// Its outgoing.
		tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

		// Reserve space for the IP and SUPERMAN headers
		skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

		// Payload would normally go here, but we don't have any.
		payload = skb_put(tx_sk, sk_len);
		memcpy(payload, sk, sk_len);

		// Setup the superman header
		shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
		skb_reset_transport_header(tx_sk);
		shdr->type = SUPERMAN_DISCOVERY_REQUEST_TYPE;					// We're preparing a discovery request packet.
		shdr->timestamp = ntohs(0);							// This will be a unique counter value for each packet, cycling round.
		shdr->payload_len = sk_len;							// A discovery request contains an SK.

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
			printk(KERN_INFO "SUPERMAN: Packet - \tRouting failed.\n");
		else
		{
			skb_dst_set(tx_sk, &rt->dst);
			dst = skb_dst(tx_sk);
			printk(KERN_INFO "SUPERMAN: Packet - \tSending packet\n");
			tx_sk->dev = dst->dev;
			dst->output(tx_sk);
		}
	}

	printk(KERN_INFO "SUPERMAN: Packet - \tUnlocking dev_base\n");
	read_unlock(&dev_base_lock);

	printk(KERN_INFO "SUPERMAN: Packet - ... Discovery Request done.\n");
}

void SendCertificateRequest(uint32_t sk_len, unsigned char* sk)
{

}

void SendAuthenticatedSKRequest(__be32 addr)
{

}

#endif
