#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/route.h>
#include <net/ip.h>

#include "packet.h"
#include "security.h"
#include "interfaces_table.h"
#include "security_table.h"

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

unsigned int send_superman_packet(struct superman_packet_info* spi, bool result)
{
	if(result)
	{
		struct flowi4 fl;
		struct rtable* rt;
		struct dst_entry *dst;

		// printk(KERN_INFO "SUPERMAN: Packet (send_superman_packet) - \t\tRouting and sending to %u.%u.%u.%u...\n", 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

		ip_send_check(spi->iph);

		flowi4_init_output(&fl, spi->skb->dev->ifindex, 0, 0, RT_SCOPE_UNIVERSE, 0, 0, spi->iph->daddr, spi->iph->saddr, 0, 0);
		rt = ip_route_output_key(dev_net(spi->skb->dev), &fl);
		if(IS_ERR(rt))
			printk(KERN_INFO "SUPERMAN: Packet (send_superman_packet) - \t\tRouting failed.\n");
		else
		{
			skb_dst_set(spi->skb, &rt->dst);
			dst = skb_dst(spi->skb);
			spi->skb->dev = dst->dev;

			// printk(KERN_INFO "SUPERMAN: Packet (send_superman_packet) - \t\tSending...\n");
			dst->output(spi->skb);
		}
	}
	else
		printk(KERN_INFO "SUPERMAN: Packet (send_superman_packet) - \t\tFailed crypto.\n");


	return FreeSupermanPacketInfo(spi);
}

unsigned int hash_then_send_superman_packet(struct superman_packet_info* spi, bool result)
{
	if(result)
	{
		return AddP2PSecurity(spi, send_superman_packet);
	}
	else
		printk(KERN_INFO "SUPERMAN: Packet (hash_then_send_superman_packet) - \t\tFailed crypto.\n");

	return FreeSupermanPacketInfo(spi);
}

bool EncapsulatePacket(struct superman_packet_info* spi)
{
	uint32_t iph_len;

	// printk(KERN_INFO "SUPERMAN: Packet - \tEncapsulating packet...\n");

	// printk(KERN_INFO "SUPERMAN: Packet - \tPacket before encapsulation...\n");
	// dump_packet(spi->skb);

	// Make sure we have enough headroom.
	if(skb_headroom(spi->skb) < sizeof(struct superman_header))
	{
		struct sk_buff* nskb;

		// printk(KERN_INFO "SUPERMAN: Packet - \t\tExpanding the packet to increase headroom...\n");

		nskb = skb_copy_expand(spi->skb, sizeof(struct superman_header), skb_tailroom(spi->skb), GFP_ATOMIC);
		if(nskb == NULL)
		{
			printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
			return false;
		}

		// Set old owner
		if (spi->skb->sk != NULL)
			skb_set_owner_w(nskb, spi->skb->sk);

		// Clean up the old one
		kfree_skb(spi->skb);
		spi->skb = nskb;

		// printk(KERN_INFO "SUPERMAN: Packet - \t\tPacket after expansion...\n");
		// dump_packet(spi->skb);
	}

	// Determine the IP header length
	iph_len = ((struct iphdr*)skb_network_header(spi->skb))->ihl << 2;

	// Allocate some of the headroom to our new header
	skb_push(spi->skb, sizeof(struct superman_header));

	// printk(KERN_INFO "SUPERMAN: Packet - \tPacket after skb_push...\n");
	// dump_packet(spi->skb);

	// Move the IP header to the start
	memmove(spi->skb->data, spi->skb->data + sizeof(struct superman_header), iph_len);

	// Grab the new IP header reference
	skb_reset_network_header(spi->skb);
	skb_set_transport_header(spi->skb, iph_len);
	spi->iph = (struct iphdr*)skb_network_header(spi->skb);

	// Fill in the superman header
	spi->shdr = (struct superman_header*)skb_transport_header(spi->skb);
	spi->shdr->type = SUPERMAN_MAX_TYPE + spi->iph->protocol;					// We're preparing a superman packet.
	spi->shdr->timestamp = htons(0);								// This will be a unique counter value for each packet, cycling round.
	spi->shdr->payload_len = htons(spi->skb->len - iph_len - sizeof(struct superman_header));	// The payload length.	

	// Update the IP header
	spi->iph->protocol = SUPERMAN_PROTOCOL_NUM;							// Our SUPERMAN protocol number
	spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) + sizeof(struct superman_header));		// Update the IP packet length
	spi->iph->check = 0;										// No checksum yet
	ip_send_check(spi->iph);

	// printk(KERN_INFO "SUPERMAN: Packet - \tPacket after encapsulation...\n");
	// dump_packet(spi->skb);

	return true;
}

bool DecapsulatePacket(struct superman_packet_info* spi)
{
	uint32_t iph_len;

	// printk(KERN_INFO "SUPERMAN: Packet - \tDecapsulating packet...\n");

	// printk(KERN_INFO "SUPERMAN: Packet - \tPacket before decapsulation...\n");
	// dump_packet(spi->skb);

	// Determine the IP header length
	iph_len = ((struct iphdr*)skb_network_header(spi->skb))->ihl << 2;

	// Update the IP header
	spi->iph->protocol = spi->shdr->type - SUPERMAN_MAX_TYPE;				// Our SUPERMAN protocol number
	spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) - sizeof(struct superman_header));	// Update the IP packet length
	spi->iph->check = 0;									// No checksum yet

	// Move the IP header inward to sit next to the payload
	memmove(spi->skb->data + sizeof(struct superman_header), spi->skb->data, iph_len);

	// Remove the space at the start of the data, back into the headroom
	skb_pull(spi->skb, sizeof(struct superman_header));

	// Update our pointers
	skb_reset_network_header(spi->skb);
	skb_set_transport_header(spi->skb, iph_len);
	spi->iph = (struct iphdr*)skb_network_header(spi->skb);
	spi->shdr = NULL;
	ip_send_check(spi->iph);

	// printk(KERN_INFO "SUPERMAN: Packet - \tPacket after decapsulation...\n");
	// dump_packet(spi->skb);

	return true;
}

void SendDiscoveryRequestPacket(uint32_t sk_len, unsigned char* sk)
{
	struct net_device *dev;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend Discovery Request...\n");
	
	INTERFACE_ITERATOR_START(dev)

	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend Discovery Request on %s...\n", dev->name);

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sk_len, GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		continue;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING | PACKET_BROADCAST;				// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	//   2 bytes  |     sk_len
	// -----------------------------
	// |  sk len  |       sk       |
	// -----------------------------

	payload = skb_put(tx_sk, sk_len);
	memcpy(payload, sk, sk_len);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_DISCOVERY_REQUEST_TYPE;					// We're preparing a discovery request packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(sk_len);						// A discovery request contains an SK.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, htonl(INADDR_BROADCAST), RT_SCOPE_UNIVERSE);	// Grab the most appropriate address.
	//iph->daddr = ((iph->saddr & 0x00FFFFFF) + 0xFF000000),			// Broadcast the message to all on the subnet
	iph->daddr = htonl(INADDR_BROADCAST);						// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	send_superman_packet(spi, true);

	INTERFACE_ITERATOR_END
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send Discovery Request done.\n");
}

void SendCertificateRequestPacket(uint32_t addr, uint32_t sk_len, unsigned char* sk)
{
	struct security_table_entry* ste;
	struct net_device *dev;
	struct in_addr;
	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend Certificate Request to %u.%u.%u.%u...\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));

	// Grab some information about the interface.
	if(!GetSecurityTableEntry(addr, &ste))
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for address %d.%d.%d.%d.\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));
		return;
	}

	// Grab a device reference. We must dereference later (dev_put).
	dev = dev_get_by_index(&init_net, ste->ifindex);
	if(dev == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for interface %i.\n", ste->ifindex);
		return;
	}

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sk_len, GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		return;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING;						// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	//   2 bytes  |     sk_len
	// -----------------------------
	// |  sk len  |       sk       |
	// -----------------------------

	payload = skb_put(tx_sk, sk_len);
	memcpy(payload, sk, sk_len);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_CERTIFICATE_REQUEST_TYPE;					// We're preparing a certificate request packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(sk_len);						// A certificate request contains an SK.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, addr, RT_SCOPE_UNIVERSE);			// Grab the most appropriate address.
	iph->daddr = addr;								// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	send_superman_packet(spi, true);
	
	// Dereference the device.
	dev_put(dev);
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send Certificate Request done.\n");
}

void SendCertificateExchangePacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate)
{
	struct security_table_entry* ste;
	struct net_device *dev;
	struct in_addr;
	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend Certificate Exchange to %u.%u.%u.%u...\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));

	// Grab some information about the interface.
	if(!GetSecurityTableEntry(addr, &ste))
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for address %d.%d.%d.%d.\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));
		return;
	}

	// Grab a device reference. We must dereference later (dev_put).
	dev = dev_get_by_index(&init_net, ste->ifindex);
	if(dev == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for interface %i.\n", ste->ifindex);
		return;
	}

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sizeof(__be16) + certificate_len, GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		return;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING;						// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	//   2 bytes  |    cert_len
	// -----------------------------
	// | Cert len |      Cert      |
	// -----------------------------

	payload = skb_put(tx_sk, certificate_len + sizeof(__be16));
	*((__be16*)payload) = htons(certificate_len);
	memcpy(payload + sizeof(__be16), certificate, certificate_len);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_CERTIFICATE_EXCHANGE_TYPE;				// We're preparing a certificate exchange packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(certificate_len + sizeof(__be16));			// A certificate exchange contains a certificate.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, addr, RT_SCOPE_UNIVERSE);			// Grab the most appropriate address.
	iph->daddr = addr;								// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	//send_superman_packet(spi, true);
	AddE2ESecurity(spi, hash_then_send_superman_packet);

	// Dereference the device.
	dev_put(dev);
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send Certificate Exchange done.\n");
}

void SendCertificateExchangeWithBroadcastKeyPacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	struct security_table_entry* ste;
	struct net_device *dev;
	struct in_addr;
	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend Certificate Exchange With Broadcast Key to %u.%u.%u.%u...\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));
	// printk(KERN_INFO "SUPERMAN: Packet - \tCertificate len: %u, Broadcast Key len: %u.\n", certificate_len, broadcast_key_len);

	// Grab some information about the interface.
	if(!GetSecurityTableEntry(addr, &ste))
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for address %d.%d.%d.%d.\n", 0x0ff & addr, 0x0ff & (addr >> 8), 0x0ff & (addr >> 16), 0x0ff & (addr >> 24));
		return;
	}

	// Grab a device reference. We must dereference later (dev_put).
	dev = dev_get_by_index(&init_net, ste->ifindex);
	if(dev == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tNo device for interface %i.\n", ste->ifindex);
		return;
	}

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sizeof(__be16) + certificate_len + sizeof(__be16) + broadcast_key_len, GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		return;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING;						// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	//   2 bytes  |    cert_len    | 2 bytes  | broadcast_key_len
	// ------------------------------------------------------------
	// | Cert len |      Cert      | bkey len |        bkey       |
	// ------------------------------------------------------------

	payload = skb_put(tx_sk, certificate_len + sizeof(__be16) + broadcast_key_len + sizeof(__be16));
	*((__be16*)payload) = htons(certificate_len);
	memcpy(payload + sizeof(__be16), certificate, certificate_len);
	*((__be16*)(payload + sizeof(__be16) + certificate_len)) = htons(broadcast_key_len);
	memcpy(payload + sizeof(__be16) + certificate_len + sizeof(__be16), broadcast_key, broadcast_key_len);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE;		// We're preparing a certificate exchange with broadcast key packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(certificate_len + sizeof(__be16) + broadcast_key_len + sizeof(__be16));	// A certificate exchange with broadcast key contains a certificate and broadcast key.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, addr, RT_SCOPE_UNIVERSE);			// Grab the most appropriate address.
	iph->daddr = addr;								// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	AddE2ESecurity(spi, hash_then_send_superman_packet);

	// Dereference the device.
	dev_put(dev);
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send Certificate Exchange With Broadcast Key done.\n");
}

void SendAuthenticatedSKRequestPacket(uint32_t addr)
{

}

void SendInvalidateSKPacket(uint32_t addr)
{
	struct net_device *dev;

	INTERFACE_ITERATOR_START(dev)

	struct in_addr;
	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend SK Invalidate...\n");

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sizeof(addr), GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		continue;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING | PACKET_BROADCAST;				// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	// ----------------
	// |  IP Address  |
	// ----------------

	payload = skb_put(tx_sk, sizeof(addr));
	*((__be32*)payload) = htonl(addr);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_SK_INVALIDATE_TYPE;					// We're preparing an SK invalidate packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(sizeof(addr));					// An SK invalidate contains an address.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, htonl(INADDR_BROADCAST), RT_SCOPE_UNIVERSE);	// Grab the most appropriate address.
	iph->daddr = htonl(INADDR_BROADCAST);						// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	AddE2ESecurity(spi, hash_then_send_superman_packet);

	INTERFACE_ITERATOR_END
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send SK Invalidate done.\n");
}


void SendBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	struct net_device *dev;

	INTERFACE_ITERATOR_START(dev)

	struct in_addr;
	struct sk_buff* tx_sk;
	struct superman_header* shdr;
	struct iphdr* iph;
	void* payload;
	struct superman_packet_info* spi;

	// printk(KERN_INFO "SUPERMAN: Packet - \tSend SK Invalidate...\n");

	// Allocate a new packet
	tx_sk = alloc_skb(sizeof(struct iphdr) + sizeof(struct superman_header) + sizeof(__be16) + broadcast_key_len, GFP_KERNEL);
	if(tx_sk == NULL)
	{
		printk(KERN_INFO "SUPERMAN: Packet - \t\tFailed to allocate a new skb.");
		continue;
	}
	tx_sk->dev = dev;
	tx_sk->pkt_type = PACKET_OUTGOING | PACKET_BROADCAST;				// Its outgoing.
	tx_sk->ip_summed = CHECKSUM_NONE;						// No need to checksum.

	// Reserve space for the IP and SUPERMAN headers
	skb_reserve(tx_sk, sizeof(struct iphdr) + sizeof(struct superman_header));

	// Payload goes here.

	// ------------------------------
	// |  BKey len | BKey           |
	// ------------------------------

	payload = skb_put(tx_sk, broadcast_key_len + sizeof(__be16));
	*((__be16*)payload) = htons(broadcast_key_len);
	memcpy(payload + sizeof(__be16), broadcast_key, broadcast_key_len);

	// Setup the superman header
	shdr = (struct superman_header*) skb_push(tx_sk, sizeof(struct superman_header));
	skb_reset_transport_header(tx_sk);
	shdr->type = SUPERMAN_SK_INVALIDATE_TYPE;					// We're preparing a broadcast key exchange packet.
	shdr->timestamp = htons(0);							// This will be a unique counter value for each packet, cycling round.
	shdr->payload_len = htons(sizeof(__be16) + broadcast_key_len);			// A broadcast key exchange packet contains a broadcast key.

	// Setup the IP header
	iph = (struct iphdr*) skb_push(tx_sk, sizeof(struct iphdr));
	skb_reset_network_header(tx_sk);
	iph->version = 4;								// IPv4 only, for now.
	iph->ihl = 5;									// Number of 32-bit words in the header (min 5)
	iph->tos = 0;									// Was TOS, now DSCP (Differentiated Services Code Point) - not required.
	iph->tot_len = htons(tx_sk->len);						// Total length of the packet
	iph->frag_off = htons(0);							// Fragment Offset - this packet is not fragmented
	iph->id = htons(0);								// The identifier is supposed to be a unique value during such that it does not repeat within the maximum datagram lifetime (MDL)
	iph->ttl = 64;									// A recommended value (in seconds)
	iph->protocol = SUPERMAN_PROTOCOL_NUM;						// Our SUPERMAN protocol number
	iph->check = 0;									// No checksum yet
	iph->saddr = inet_select_addr(dev, htonl(INADDR_BROADCAST), RT_SCOPE_UNIVERSE);	// Grab the most appropriate address.
	iph->daddr = htonl(INADDR_BROADCAST);						// Broadcast the message to all on the subnet

	spi = MallocSupermanPacketInfo(0, tx_sk, NULL, NULL, NULL);
	AddE2ESecurity(spi, hash_then_send_superman_packet);

	INTERFACE_ITERATOR_END
	// printk(KERN_INFO "SUPERMAN: Packet - \t... Send Broadcast Key Exchange done.\n");
}

#endif
