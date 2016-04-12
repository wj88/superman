#ifdef __KERNEL__

#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>

#include "netfilter.h"
#include "packet_info.h"
#include "packet.h"
#include "netlink.h"
#include "interfaces_table.h"
#include "security_table.h"
#include "security.h"
#include "processor.h"
#include "queue.h"

#define HOOK_DEF(func_name, ops_name, hook_num)																	\
unsigned int func_name(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state);		\
static struct nf_hook_ops ops_name = {																		\
	.owner      	= THIS_MODULE,																		\
	.hook 		= func_name,																		\
	.hooknum 	= hook_num,																		\
	.pf		= PF_INET,																		\
	.priority	= NF_IP_PRI_FIRST																	\
};

// Useful reference: http://phrack.org/issues/61/13.html

// After sanity checks, before routing decisions.
HOOK_DEF(hook_prerouting, nf_hook_prerouting, NF_IP_PRE_ROUTING)
// After routing decisions if packet is for this host.
HOOK_DEF(hook_localin, nf_hook_localin, NF_IP_LOCAL_IN)
// If the packet is destined for another interface.
//HOOK_DEF(hook_forward, nf_hook_forward, NF_IP_FORWARD)
// For packets coming from local processes on their way out.
HOOK_DEF(hook_localout, nf_hook_localout, NF_IP_LOCAL_OUT)
// Just before outbound packets "hit the wire".
HOOK_DEF(hook_postrouting, nf_hook_postrouting, NF_IP_POST_ROUTING)


/*
--------------------------------------------------

		Transport Layer

--------------------------------------------------
	|	 Network Layer		^
	v				|
    LOCAL OUT		            LOCAL IN
	|				^
	v				|
  ---------------			|
  |   ROUTING	|			|
  ---------------			|
	|			  ---------------
	|<-----------FORWARD<-----|   ROUTING	|
	|			  ---------------
	|				^
	v				|
   POST ROUTING			   PRE ROUTING
	|				^
	v				|
--------------------------------------------------

		Data Link Layer

--------------------------------------------------


SUPERMAN Security:

P2P (HMAC):
	Added: 		Post Routing
	Removed:	Pre Routing
E2E (AEAD):
	Added:		Local Out
	Removed:	Local In
Exceptions:
	Where nodes are yet to be added to the routing table:
		SUPERMAN_DISCOVERY_REQUEST_TYPE
		SUPERMAN_CERTIFICATE_REQUEST_TYPE
		SUPERMAN_CERTIFICATE_EXCHANGE_TYPE
		SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE
	Where we're intercepting packets:
		SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE
		SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE


Packet Processing Summary:

case SUPERMAN_DISCOVERY_REQUEST_TYPE:
case SUPERMAN_CERTIFICATE_REQUEST_TYPE:
	Secured:	No
	Broadcast:	Yes
	Sent:		Post Routing (not yet in the routing table)
	Received:
		Processed:	Pre Routing (not yet in the routing table)
		Dropped:	Pre Routing (not yet in the routing table)

case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:
case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:
	Secured:	Yes
	Broadcast:	No
	Sent:		Post Routing (not yet in the routing table)
	Receives:
		Processed:	Pre Routing (not yet in the routing table)
		Dropped:	Pre Routing (not yet in the routing table)

SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE
	Secured:	Yes
	Broadcast:	No
	Sent:		Local Out
	Received:
		Processed:	Forward (intercepting: if we have the SK, send response)				
		Dropped:	Forward (intercepting: if we have the SK, drop, otherwise will be forward)

SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE
	Secured:	Yes
	Broadcast:	No
	Sent:		Local Out
	Received:
		Processes:	Pre Routing (intercepting: if we don't have the SK, take a copy)
		Dropped:	Local In (if it was for us, we'll have processed in pre routing)

SUPERMAN_SK_INVALIDATE_TYPE
	Secured:	Yes
	Broadcast:	Yes
	Sent:		Local Out
	Received:
		Processed:	Local In
		Dropped:	Local In

SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE
	Secured:	Yes
	Broadcast:	Yes
	Sent:		Local Out
	Received:
		Processed:	Local In
		Dropped:	Local In

ANY_OTHER_TYPE
	Secured:	Yes
	Broadcast:	Maybe
	Sent:		Local Out
	Received:
		Processed:	Local In
		Dropped:	NA


-----------------------------------------------
Special case note:

These types are complicated:
SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE
SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE

The problem is as follows:

------------------------------------------
| IP Header | Transport Header & Payload |
------------------------------------------
		|
		v
----------------------------------------------------------------------					|
| IP Header | SUPERMAN Header | Encrypted Transport Header & Payload |					|--- Local In / Out
----------------------------------------------------------------------					|
		|
		v
------------------------------------------------------------------------------------------		|
| IP Header | Minimal IP Header | SUPERMAN Header | Encrypted Transport Header & Payload |		|--- Routing (e.g  AODV)
------------------------------------------------------------------------------------------		|
		|
		v
-------------------------------------------------------------------------------------------------	|
| IP Header | Minimal IP Header | SUPERMAN Header | Encrypted Transport Header & Payload | HMAC |	|--- Post / Pre Routing
-------------------------------------------------------------------------------------------------	|

This is the typical flow of a packet through the network layer. A  packet which we're routing onward would
have it's HMAC removed at Pre Routing, pass through routing, flag up in Forward, then have  it an HMAC
reattached in Post Routing (as per the diagram further up).

These two packet types are not AEAD'd, because they have very little value in securing them and the
response.is sent our with discovery requests anyway. They are HMAC'd to ensure they're not tampered with.

The problem is that the we're supposed to be able to intercept one of these and reply on behalf of the
destination if we have their SK, yet the SUPERMAN header is not going to be in a fixed location. The source
code for AODV-UU adds a Minimal IP Header to the packet so that it can remember the intended destination
whilst addressing the packet for the next hop but whose to say every routing implementation chooses this
approach. We cannot guarentee this.

What we can do for these packets is append something to the end, before the HMAC to allow us to check
the packet at Pre Routing, allow us to intercept it and look backward to find the SUPERMAN Header.


*/



inline bool is_valid_ip_packet(struct sk_buff* skb)
{
	// Does this packet contain IP data?
	return skb && ip_hdr(skb);
}


unsigned int process_certificate_exchange_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.

	uint32_t certificate_len;
	unsigned char* certificate;

	// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tProcessing the certificate exchange...\n");
	struct certificate_exchange_payload* p = (struct certificate_exchange_payload*)spi->payload;

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(ntohs(spi->shdr->payload_len) >= CERTIFICATE_EXCHANGE_PAYLOAD_LEN(ntohs(0)) && ntohs(spi->shdr->payload_len) >= CERTIFICATE_EXCHANGE_PAYLOAD_LEN(ntohs(p->certificate_len)))
	{
		certificate_len = ntohs(p->certificate_len);
		certificate = p->certificate;
		ReceivedSupermanCertificateExchange(spi->e2e_addr, certificate_len, certificate);
	}
	else
	{
		printk(KERN_INFO "SUPERMAN: Netfilter - Payload size mismatch, expected: %d, received: %lu.\n", ntohs(spi->shdr->payload_len), CERTIFICATE_EXCHANGE_PAYLOAD_LEN(ntohs(p->certificate_len)));
	}

	spi->use_callback = false;
	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
	return FreeSupermanPacketInfo(spi);
}

unsigned int process_certificate_exchange_with_broadcast_key_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.

	uint32_t certificate_len;
	unsigned char* certificate;
	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;
	struct certificate_exchange_with_broadcast_key_payload* p;

	//printk(KERN_INFO "SUPERMAN: Netfilter - \t\tProcessing the certificate exchange with broadcast key...\n");
	p = (struct certificate_exchange_with_broadcast_key_payload*)spi->payload;

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(ntohs(spi->shdr->payload_len) >= CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_PAYLOAD_LEN(ntohs(0), ntohs(0)) && ntohs(spi->shdr->payload_len) >= CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_PAYLOAD_LEN(ntohs(p->certificate_len), ntohs(p->broadcast_key_len)))
	{
		certificate_len = ntohs(p->certificate_len);
		broadcast_key_len = ntohs(p->broadcast_key_len);

		// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tCertificate length: %u\n", certificate_len);
		// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tBroadcast Key length: %u\n", broadcast_key_len);

		certificate = p->data;
		broadcast_key = (p->data + certificate_len);

		ReceivedSupermanCertificateExchangeWithBroadcastKey(spi->e2e_addr, certificate_len, certificate, broadcast_key_len, broadcast_key);
	}
	else
	{
		printk(KERN_INFO "SUPERMAN: Netfilter - Payload size mismatch, expected: %d, received: %lu.\n", ntohs(spi->shdr->payload_len), CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_PAYLOAD_LEN(ntohs(p->certificate_len), ntohs(p->broadcast_key_len)));
	}

	spi->use_callback = false;
	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
	// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tFinished processing the certificate exchange with broadcast key, result: %d.\n", spi->result);
	return FreeSupermanPacketInfo(spi);
}

unsigned int process_broadcast_key_exchange_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.

	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;
	struct broadcast_key_exchange_payload* p;

	//printk(KERN_INFO "SUPERMAN: Netfilter - \t\tProcessing the broadcast key exchange...\n");
	p = (struct broadcast_key_exchange_payload*)spi->payload;

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(ntohs(spi->shdr->payload_len) >= BROADCAST_KEY_EXCHANGE_PAYLOAD_LEN(ntohs(0)) && ntohs(spi->shdr->payload_len) >= BROADCAST_KEY_EXCHANGE_PAYLOAD_LEN(ntohs(p->broadcast_key_len)))
	{
		broadcast_key_len = ntohs(p->broadcast_key_len);
		broadcast_key = p->broadcast_key;

		ReceivedSupermanBroadcastKeyExchange(broadcast_key_len, broadcast_key);
	}
	else
	{
		printk(KERN_INFO "SUPERMAN: Netfilter - Payload size mismatch, expected: %d, received: %lu.\n", ntohs(spi->shdr->payload_len), BROADCAST_KEY_EXCHANGE_PAYLOAD_LEN(ntohs(p->broadcast_key_len)));
	}

	spi->use_callback = false;
	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
	// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tFinished processing the broadcast key exchange, result: %d.\n", spi->result);
	return FreeSupermanPacketInfo(spi);
}


unsigned int process_sk_invalidate_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.
	struct sk_invalidate_payload* payload;
	__be32 addr;

	//printk(KERN_INFO "SUPERMAN: Netfilter - \t\tProcessing the invalidate sk...\n");
	payload = (struct sk_invalidate_payload*)spi->payload;
	addr = payload->addr;

	ReceivedSupermanSKInvalidate(addr);

	spi->result = NF_DROP;				// Don't let an Invalidate SK propogate higher up the stack
	return FreeSupermanPacketInfo(spi);
}

unsigned int process_authenticated_sk_request(struct superman_packet_info* spi)
{
	struct security_table_entry* security_details;
	struct sk_request_payload* payload;
	uint32_t originaddr;
	uint32_t targetaddr;

	printk(KERN_INFO "SUPERMAN: Netfilter - process_authenticated_sk_request.\n");

	payload = (struct sk_request_payload*)spi->payload;
	originaddr = ntohl(payload->originaddr);
	targetaddr = ntohl(payload->targetaddr);

	// If we don't have it, we can request it too.
	if(!GetSecurityTableEntry(targetaddr, &security_details))
		SendAuthenticatedSKRequestPacket(originaddr, targetaddr);

	// Otherwise, we can share the answer we already have.
	else
		SendAuthenticatedSKResponsePacket(originaddr, targetaddr, security_details->sk_len, security_details->sk);

	spi->result = NF_DROP;				// Don't let an Authenticated SK Request propogate higher up the stack
	return FreeSupermanPacketInfo(spi);
}

unsigned int process_authenticated_sk_response(struct superman_packet_info* spi)
{
	struct security_table_entry* security_details;
	struct sk_response_payload* payload;
	uint32_t originaddr;
	uint32_t targetaddr;
	uint32_t sk_len;
	unsigned char* sk;

	printk(KERN_INFO "SUPERMAN: Netfilter - process_authenticated_sk_response.\n");

	payload = (struct sk_response_payload*)spi->payload;
	originaddr = ntohl(payload->originaddr);
	targetaddr = ntohl(payload->targetaddr);
	sk_len = (uint32_t)(ntohs(payload->sk_len));
	sk = (unsigned char*)(payload->sk);

	// Grab a copy if we don't have it already.
	if(!GetSecurityTableEntry(targetaddr, &security_details))
	{
		ReceivedSupermanAuthenticatedSKResponse(targetaddr, sk_len, sk, spi->shdr->timestamp, spi->skb->skb_iif);
	}

	// If it wasn't actually destined for us, pass it one.
	if(spi->p2p_our_addr != originaddr)
		SendAuthenticatedSKResponsePacket(originaddr, targetaddr, sk_len, sk);

	spi->result = NF_DROP;				// Don't let an Authenticated SK Request propogate higher up the stack
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_prerouting_removed_e2e(struct superman_packet_info* spi, bool result)
{

	// NOTE: We need to free our spi.
	if(result)
	{
		// Everything from here will be unencrypted

		// Deal with special case unencapsulated SUPERMAN packets which are secured!
		if(spi->shdr)
		{
			switch(spi->shdr->type)
			{
				case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:
					return process_authenticated_sk_request(spi);
					break;
				case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:
					return process_authenticated_sk_response(spi);
					break;
			}
		}
	}

	// There should be no other packets which reach this point.
	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_prerouting_removed_p2p(struct superman_packet_info* spi, bool result)
{
	// NOTE: We need to free our spi.
	if(result)
	{	
		// Everything from here will be encrypted / authenticatable

		// Deal with special case unencapsulated SUPERMAN packets which are secured!
		if(spi->shdr)
		{
			switch(spi->shdr->type)
			{
				case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:				// It's an SK Request
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;
				case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:				// It's an SK Response
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;
			}
		}

		// For all other packet types, we call their callback method, if we stole the packet.
		if(spi->result != NF_STOLEN)
			spi->result = NF_ACCEPT;
		spi->use_callback = true;
	}

	// Cleanup the SPI;
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_localout_add_e2e(struct superman_packet_info* spi, bool result)
{
	if(result)
	{
		// Call their callback method, if we stole the packet.
		if(spi->result != NF_STOLEN) spi->result = NF_ACCEPT;
		spi->use_callback = true;
	}

	// Cleanup the SPI;
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_localin_remove_e2e(struct superman_packet_info* spi, bool result)
{
	if(result)
	{
		switch(spi->shdr->type)
		{
			case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:				// It's a Certificate Exchange
				// printk(KERN_INFO "SUPERMAN: Netfilter (hook_localin_remove_e2e) calling process_certificate_exchange...\n");
				return process_certificate_exchange_packet(spi);
				break;

			case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
				// printk(KERN_INFO "SUPERMAN: Netfilter (hook_localin_remove_e2e) calling process_certificate_exchange_with_broadcast_key_packet...\n");
				return process_certificate_exchange_with_broadcast_key_packet(spi);
				break;
			case SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE:					// It's a Broadcast Key Exchange
				return process_broadcast_key_exchange_packet(spi);
				break;
			case SUPERMAN_SK_INVALIDATE_TYPE:					// It's an Invalidate SK
				return process_sk_invalidate_packet(spi);
				break;
		}

		if(!DecapsulatePacket(spi))
		{
			// Failed to decapsulate packet.
			printk(KERN_INFO "SUPERMAN: Netfilter (hook_localin_remove_e2e) failed to decapsulate packet.\n");
			if(spi->result != NF_STOLEN) spi->result = NF_DROP;
		}
		else
		{
			// Call their callback method, if we stole the packet.
			if(spi->result != NF_STOLEN) spi->result = NF_ACCEPT;
			spi->use_callback = true;
		}
	}

	// Cleanup the SPI;
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_postrouting_add_p2p(struct superman_packet_info* spi, bool result)
{
	if(result)
	{
		// Call their callback method, if we stole the packet.
		if(spi->result != NF_STOLEN) spi->result = NF_ACCEPT;
		spi->use_callback = true;
	}

	// Cleanup the SPI;
	return FreeSupermanPacketInfo(spi);
}

unsigned int hook_postouting_post_sk_response(struct superman_packet_info* spi, bool result)
{
	if(result)
		return AddP2PSecurity(spi, &hook_postrouting_add_p2p);
	else
		return FreeSupermanPacketInfo(spi);
}

unsigned int hook_prerouting_post_sk_response(struct superman_packet_info* spi, bool result)
{
	if(result)
		return RemoveP2PSecurity(spi, &hook_prerouting_removed_p2p);
	else
		return FreeSupermanPacketInfo(spi);
}

unsigned int hook_localin_post_sk_response(struct superman_packet_info* spi, bool result)
{
	if(result)
		return RemoveE2ESecurity(spi, &hook_localin_remove_e2e);
	else
		return FreeSupermanPacketInfo(spi);
}

unsigned int hook_localout_post_sk_response(struct superman_packet_info* spi, bool result)
{
	if(result)
		return AddE2ESecurity(spi, &hook_localout_add_e2e);
	else
		return FreeSupermanPacketInfo(spi);
}

// After sanity checks, before routing decisions.
unsigned int hook_prerouting(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING)\n");

	// Let non-IP packets and those of interfaces we're not monitoring.
	if(!is_valid_ip_packet(skb) || !HasInterfacesTableEntry(state->in->ifindex))
	{
		// if(!is_valid_ip_packet(skb))
		// 	printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \tNot a valid IP packet.\n");
		// else
		// 	printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \tInterface not found in interfaces table: %u.\n", in->ifindex);

		return NF_ACCEPT;
	}

	// Construct a new SPI to handle this packet.
	spi = MallocSupermanPacketInfo(ops, skb, state);

	// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \tPacket Received from %u.%u.%u.%u to %u.%u.%u.%u...\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24), 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

	// Deal with special case unencapsulated SUPERMAN packets which are not secured!
	if(spi->shdr)
	{
		// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - (%u) %s, %d bytes recieved from %u.%u.%u.%u.\n", spi->shdr->type, lookup_superman_packet_type_desc(spi->shdr->type), spi->skb->len, 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24));

		// Perform a basic sanity check on the packet.
		if(ntohs(spi->shdr->payload_len) > spi->iph->tot_len - (skb_network_header_len(skb) + sizeof(struct superman_header)))
		{
			printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - Superman packet failed initial basic sanity check.\n");
			printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \tPayload length, expected: %d, available: %lu.\n", ntohs(spi->shdr->payload_len), spi->iph->tot_len - (skb_network_header_len(skb) + sizeof(struct superman_header)));
			dump_packet(spi->skb);
			spi->result = NF_DROP;
			return FreeSupermanPacketInfo(spi);
		}

		switch(spi->shdr->type)
		{
			case SUPERMAN_DISCOVERY_REQUEST_TYPE:			// It's a Discovery Request
				// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tDiscovery Request Packet.\n");
				ReceivedSupermanDiscoveryRequest(spi->e2e_addr, ntohs(spi->shdr->payload_len), spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
				break;

			case SUPERMAN_CERTIFICATE_REQUEST_TYPE:			// It's a Certificate Request
				// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tCertificate Request Packet.\n");
				ReceivedSupermanCertificateRequest(spi->e2e_addr, ntohs(spi->shdr->payload_len), spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
				break;
		}

		// Are we not supposed to do P2P on this packet
		if(!spi->p2p_secure_packet)
		{
			spi->result = NF_ACCEPT;
			return FreeSupermanPacketInfo(spi);
		}

		// Do we have the required security details of the source to remove
		// the P2P... if not we must queue up the packet and request them.
		if(spi->p2p_secure_packet && !spi->p2p_has_security_details)
		{
			// If it the broadcast key we don't have, ditch the packet.
			if(spi->p2p_use_broadcast_key)
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tBroadcast packet but we don't have a broadcast key.\n");

				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
			}
			// Otherwise queue the packet and send an SK request.
			else
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

				spi->result = NF_STOLEN;
				EnqueuePacket(spi, spi->p2p_neighbour_addr, &hook_prerouting_post_sk_response);
				SendAuthenticatedSKRequestPacket(0, spi->p2p_neighbour_addr);
				return spi->result;
			}
		}
		
		// For all other packet types, they must pass the hmac check!
		// NOTE: The callback becomes responsible for clearing up the SPI.
		// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tRemoving P2P security...\n");
		return RemoveP2PSecurity(spi, &hook_prerouting_removed_p2p);
	}

	// We should never get here. If we do it means we do not have a SUPERMAN header.
	spi->result = NF_DROP;
	return FreeSupermanPacketInfo(spi);
}

// After routing decisions if packet is for this host.
unsigned int hook_localin(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN)\n");

	// Let non-IP packets and those of interfaces we're not monitoring.
	if(!is_valid_ip_packet(skb) || !HasInterfacesTableEntry(state->in->ifindex))
		return NF_ACCEPT;

	// Construct a new SPI to handle this packet.
	spi = MallocSupermanPacketInfo(ops, skb, state);

	// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN) - \tfrom %u.%u.%u.%u to %u.%u.%u.%u...\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24), 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

	// Deal with special case unencapsulated SUPERMAN packets which are not secured!
	if(spi->shdr)
	{
		// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN) - (%u) %s, %d bytes recieved from %u.%u.%u.%u.\n", spi->shdr->type, lookup_superman_packet_type_desc(spi->shdr->type), spi->skb->len, 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24));

		// If we don't need to apply E2E, let it through now.
		if(!spi->e2e_secure_packet)
		{
			spi->result = NF_ACCEPT;
			return FreeSupermanPacketInfo(spi);
		}

		// Do we have the required security details of the source to decrypt
		// the E2E... if not we must queue up the packet and request them.
		if(spi->e2e_secure_packet && !spi->e2e_has_security_details)
		{
			// If it the broadcast key we don't have, ditch the packet.
			if(spi->e2e_use_broadcast_key)
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN) - \t\tBroadcast packet but we don't have a broadcast key.\n");

				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
			}
			// Otherwise queue the packet and send an SK request.
			else
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

				spi->result = NF_STOLEN;
				EnqueuePacket(spi, spi->e2e_addr, &hook_localin_post_sk_response);
				SendAuthenticatedSKRequestPacket(0, spi->e2e_addr);
				return spi->result;
			}
		}
	
		return RemoveE2ESecurity(spi, &hook_localin_remove_e2e);
	}

	// We should never get here. If we do it means we do not have a SUPERMAN header.
	spi->result = NF_DROP;
	return FreeSupermanPacketInfo(spi);
}

/*

// If the packet is destined for another interface.
unsigned int hook_forward(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	//if(is_valid_ip_packet(skb) && is_superman_packet(skb))
		return NF_ACCEPT;
	//else
	//	return NF_DROP;           	// Drop ALL packets
}

*/


// For packets coming from local processes on their way out.
unsigned int hook_localout(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT)\n");

	// Let non-IP packets and those of interfaces we're not monitoring.
	if(!is_valid_ip_packet(skb) || !HasInterfacesTableEntry(state->out->ifindex))
		return NF_ACCEPT;

	// Construct a new SPI to handle this packet.
	spi = MallocSupermanPacketInfo(ops, skb, state);

	// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - \tPacket Send from %u.%u.%u.%u to %u.%u.%u.%u...\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24), 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

	if(!EncapsulatePacket(spi))
	{
		spi->result = NF_DROP;
		return FreeSupermanPacketInfo(spi);
	}

	if(spi->shdr)
	{
		// printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - (%u) %s, %d bytes sending to %u.%u.%u.%u.\n", spi->shdr->type, lookup_superman_packet_type_desc(spi->shdr->type), spi->skb->len, 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

		// If we don't need to apply E2E, let it through now.
		if(!spi->e2e_secure_packet)
		{
			spi->result = NF_ACCEPT;
			return FreeSupermanPacketInfo(spi);
		}

		// Do we have the required security details of the source to remove
		// the P2P... if not we must queue up the packet and request them.
		if(spi->e2e_secure_packet && !spi->e2e_has_security_details)
		{
			// If it the broadcast key we don't have, ditch the packet.
			if(spi->e2e_use_broadcast_key)
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - \t\tBroadcast packet but we don't have a broadcast key.\n");

				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
			}
			// Otherwise queue the packet and send an SK request.
			else
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

				spi->result = NF_STOLEN;
				EnqueuePacket(spi, spi->e2e_addr, &hook_localout_post_sk_response);
				SendAuthenticatedSKRequestPacket(0, spi->e2e_addr);
				return spi->result;
			}
		}

		//printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - \t\tAdding E2E security.\n");
		return AddE2ESecurity(spi, &hook_localout_add_e2e);
	}

	// We should never get here. If we do it means we do not have a SUPERMAN header.
	spi->result = NF_DROP;
	return FreeSupermanPacketInfo(spi);
}

// Just before outbound packets "hit the wire".
unsigned int hook_postrouting(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING)\n");

	// Let non-IP packets and those of interfaces we're not monitoring.
	if(!is_valid_ip_packet(skb) || !HasInterfacesTableEntry(state->out->ifindex))
		return NF_ACCEPT;

	// Construct a new SPI to handle this packet.
	spi = MallocSupermanPacketInfo(ops, skb, state);

	// Deal with special case SUPERMAN packets which we leave alone (after all, we made them)!
	if(spi->shdr)
	{
		// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - (%u) %s, %d bytes sending to %u.%u.%u.%u.\n", spi->shdr->type, lookup_superman_packet_type_desc(spi->shdr->type), spi->skb->len, 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

		switch(spi->shdr->type)
		{
			case SUPERMAN_DISCOVERY_REQUEST_TYPE:			// It's a Discovery Request
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tDiscovery Request Packet.\n");
				spi->result = NF_ACCEPT;
				return FreeSupermanPacketInfo(spi);
				break;
			case SUPERMAN_CERTIFICATE_REQUEST_TYPE:			// It's a Certificate Request
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tCertificate Request Packet.\n");
				spi->result = NF_ACCEPT;
				return FreeSupermanPacketInfo(spi);
				break;
/*
			case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:		// It's a Certificate Exchange
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tCertificate Exchange Packet.\n");
				//spi->result = NF_ACCEPT;
				//return FreeSupermanPacketInfo(spi);
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen a Certificate Exchange, letting through.\n");
				break;
			case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tCertificate Exchange With Broadcast Key Packet.\n");
				//spi->result = NF_ACCEPT;
				//return FreeSupermanPacketInfo(spi);
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen a Certificate Exchange with Broadcast Key, letting through.\n");
				break;
			case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen an SK Request, letting through.\n");
				break;
			case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:
				//printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen an SK Response, letting through.\n");
				break;
*/
		}

		// Are we not supposed to do P2P on this packet
		if(!spi->p2p_secure_packet)
		{
			spi->result = NF_ACCEPT;
			return FreeSupermanPacketInfo(spi);
		}

		// Do we have the required security details of the source to remove
		// the P2P... if not we must queue up the packet and request them.
		if(spi->p2p_secure_packet && !spi->p2p_has_security_details)
		{
			// If it the broadcast key we don't have, ditch the packet.
			if(spi->p2p_use_broadcast_key)
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tBroadcast packet but we don't have a broadcast key.\n");

				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
			}
			// Otherwise queue the packet and send an SK request.
			else
			{
				printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

				spi->result = NF_STOLEN;
				EnqueuePacket(spi, spi->p2p_neighbour_addr, &hook_postouting_post_sk_response);
				SendAuthenticatedSKRequestPacket(0, spi->p2p_neighbour_addr);
				return spi->result;
			}
		}

		//printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tAdding P2P security.\n");
		return AddP2PSecurity(spi, &hook_postrouting_add_p2p);
	}

	// We should never get here. If we do it means we do not have a SUPERMAN header.
	spi->result = NF_DROP;
	return FreeSupermanPacketInfo(spi);
}

/*
The proc entry init and deinit functions deal with construction and destruction.
*/
bool InitNetFilter(void)
{
	nf_register_hook(&nf_hook_prerouting);
	nf_register_hook(&nf_hook_localin);
	nf_register_hook(&nf_hook_localout);
	nf_register_hook(&nf_hook_postrouting);
/*
	nf_register_hook(&nf_hook_forward);
*/

	return true;
}

void DeInitNetFilter(void)
{
	nf_unregister_hook(&nf_hook_prerouting);
	nf_unregister_hook(&nf_hook_localin);
	nf_unregister_hook(&nf_hook_localout);
	nf_unregister_hook(&nf_hook_postrouting);
/*
	nf_unregister_hook(&nf_hook_forward);
*/
}

#endif
