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

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(ntohs(spi->shdr->payload_len) >= sizeof(__be16))
	{
		certificate_len = ntohs(*((__be16*) spi->payload));
		// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tCertificate length: %u\n", certificate_len);

		if(ntohs(spi->shdr->payload_len) >= sizeof(__be16) + certificate_len)
		{
			certificate = (unsigned char*)(spi->payload + sizeof(__be16));
			ReceivedSupermanCertificateExchange(spi->addr, certificate_len, certificate);
		}
		else
			printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (certificate).\n");
	}
	else
		printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (certificate_len).\n");

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

	// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tProcessing the certificate exchange with broadcast key...\n");

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(ntohs(spi->shdr->payload_len) >= sizeof(__be16))
	{
		certificate_len = ntohs(*((__be16*) spi->payload));
		// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tCertificate length: %u\n", certificate_len);

		if(ntohs(spi->shdr->payload_len) >= sizeof(__be16) + certificate_len)
		{
			certificate = (unsigned char*)(spi->payload + sizeof(__be16));

			if(ntohs(spi->shdr->payload_len) >= sizeof(__be16) + certificate_len + sizeof(__be16))
			{
				broadcast_key_len = ntohs(*((__be16*) (spi->payload + sizeof(__be16) + certificate_len)));
				// printk(KERN_INFO "SUPERMAN: Netfilter - \t\tBroadcast Key length: %u\n", broadcast_key_len);

				if(ntohs(spi->shdr->payload_len) >= sizeof(__be16) + certificate_len + sizeof(__be16) + broadcast_key_len)
				{
					broadcast_key = (unsigned char*)(spi->payload + sizeof(__be16) + certificate_len + sizeof(__be16));
					ReceivedSupermanCertificateExchangeWithBroadcastKey(spi->addr, certificate_len, certificate, broadcast_key_len, broadcast_key);
				}
				else
					printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (broadcast key).\n");
			}
			else
				printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (broadcast_key_len).\n");
		}
		else
			printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (certificate).\n");
	}
	else
		printk(KERN_INFO "SUPERMAN: Netfilter - \t\t\tPayload size mismatch (certificate_len).\n");

	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
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
		ReceivedSupermanAuthenticatedSKResponse(targetaddr, sk_len, sk, spi->shdr->timestamp, spi->skb->skb_iif);

	// Pass on the answer.
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
				case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:				// It's a Certificate Exchange
					return process_certificate_exchange_packet(spi);
					break;

				case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
					return process_certificate_exchange_with_broadcast_key_packet(spi);
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
				case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:				// It's a Certificate Exchange
					spi->security_flag = 2;
					//return process_certificate_exchange_packet(spi);
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;

				case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
					spi->security_flag = 2;
					//return process_certificate_exchange_with_broadcast_key_packet(spi);
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;
				case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:				// It's an SK Request
					return process_authenticated_sk_request(spi);
					break;
				case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:				// It's an SK Response
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;
			}
		}

/*

			case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:		// It's an Authenticated SK Request
				printk(KERN_INFO "SUPERMAN: Netfilter - Certificate Exchange With Broadcast Key Packet.\n");
				RemoveP2PSecurity(skb, removed_authenticated_sk_request_p2p_callback, true, true);

				if(HaveSK(skb)) {				// If we already have the SK, we can reply with it (no need for routing / forwarding)
					SendAuthenticatedSKResponse(skb);	// Send the SK we already have.
					return NF_DROP;				// Don't let a Authenticated SK Request propogate higher up the stack
				} else
					return NF_ACCEPT;			// We don't yet have the SK, let the request propogate, ie, be routed.

				break;


			case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:
				if(ReceiveAuthenticatedSKResponse(skb))		// Process the received Authenticated SK Response (taking a copy). If it was for us, don't propogate.
					return NF_DROP;				// It was for us, don't let it propogate.
				else
					return NF_ACCEPT;			// It wasn't for us, propogate (although we took a copy!)
				break;

*/


		// For all other packet types, we call their callback method, if we stole the packet.
		if(spi->result != NF_STOLEN) spi->result = NF_ACCEPT;
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
		if(!DecapsulatePacket(spi))
		{
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

unsigned int hook_prerouting_post_sk_response(struct superman_packet_info* spi, bool result)
{
	if(result)
		return RemoveP2PSecurity(spi, &hook_prerouting_removed_p2p);
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
	if(spi->secure_packet)
	{
		if(spi->shdr)
		{
			printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - (%u) %s, %d bytes recieved from %u.%u.%u.%u.\n", spi->shdr->type, lookup_superman_packet_type_desc(spi->shdr->type), spi->skb->len, 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24));


			if(ntohs(spi->shdr->payload_len) > spi->iph->tot_len - (skb_network_header_len(skb) + sizeof(struct superman_header)))
			{
				//printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - Superman packet failed initial basic sanity check.\n");
				//printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \tPayload length, expected: %d, available: %lu.\n", ntohs(spi->shdr->payload_len), spi->iph->tot_len - (skb_network_header_len(skb) + sizeof(struct superman_header)));
				dump_packet(spi->skb);
				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
			}

			switch(spi->shdr->type)
			{
				case SUPERMAN_DISCOVERY_REQUEST_TYPE:			// It's a Discovery Request
					// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tDiscovery Request Packet.\n");
					ReceivedSupermanDiscoveryRequest(spi->addr, ntohs(spi->shdr->payload_len), spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
					spi->result = NF_DROP;
					return FreeSupermanPacketInfo(spi);
					break;

				case SUPERMAN_CERTIFICATE_REQUEST_TYPE:			// It's a Certificate Request
					// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tCertificate Request Packet.\n");
					ReceivedSupermanCertificateRequest(spi->addr, ntohs(spi->shdr->payload_len), spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
					spi->result = NF_DROP;
					return FreeSupermanPacketInfo(spi);
					break;
			}

			// Do we have the required security details of the source to remove
			// the P2P... if not we must queue up the packet and request them.
			if(spi->secure_packet && !spi->has_security_details)
			{
				// If it the broadcast key we don't have, ditch the packet.
				if(spi->use_broadcast_key)
				{
					// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tBroadcast packet but we don't have a broadcast key.\n");

					spi->result = NF_DROP;
					return FreeSupermanPacketInfo(spi);
				}
				// Otherwise queue the packet and send an SK request.
				else
				{
					// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

					spi->result = NF_STOLEN;
					EnqueuePacket(spi, &hook_prerouting_post_sk_response);
					SendAuthenticatedSKRequestPacket(0, spi->addr);
					return spi->result;
				}
			}

			// For all other packet types, they must pass the hmac check!
			// NOTE: The callback becomes responsible for clearing up the SPI.
			// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tRemoving P2P security...\n");
			return RemoveP2PSecurity(spi, &hook_prerouting_removed_p2p);
		}
		else
		{
			spi->result = NF_DROP;
		}
	}

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

	printk(KERN_INFO "SUPERMAN: Netfilter (LOCALIN) - \tfrom %u.%u.%u.%u to %u.%u.%u.%u...\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24), 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

	return RemoveE2ESecurity(spi, &hook_localin_remove_e2e);
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

	// If this isn't an SK request, we'll need to encapsulate.
	if(spi->shdr != NULL && spi->shdr->type == SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE)
	{
		printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - Letting through an SK Request.\n");
		spi->result = NF_ACCEPT;
		return FreeSupermanPacketInfo(spi);
	}
/*
	if(spi->shdr != NULL && spi->shdr->type == SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE)
	{
		printk(KERN_INFO "SUPERMAN: Netfilter (LOCALOUT) - Letting through an SK Response.\n");
		spi->result = NF_ACCEPT;
		return FreeSupermanPacketInfo(spi);
	}
*/

	if(!EncapsulatePacket(spi))
	{
		spi->result = NF_DROP;
		return FreeSupermanPacketInfo(spi);
	}

	// Do we have the required security details of the source to remove
	// the P2P... if not we must queue up the packet and request them.
	if(spi->secure_packet && !spi->has_security_details)
	{
		// If it the broadcast key we don't have, ditch the packet.
		if(spi->use_broadcast_key)
		{
			// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tBroadcast packet but we don't have a broadcast key.\n");

			spi->result = NF_DROP;
			return FreeSupermanPacketInfo(spi);
		}
		// Otherwise queue the packet and send an SK request.
		else
		{
			// printk(KERN_INFO "SUPERMAN: Netfilter (PREROUTING) - \t\tWe don't have the the security details. Queuing packet and sending an SK Request.\n");

			spi->result = NF_STOLEN;
			EnqueuePacket(spi, &hook_localout_post_sk_response);
			SendAuthenticatedSKRequestPacket(0, spi->addr);
			return spi->result;
		}
	}

	return AddE2ESecurity(spi, &hook_localout_add_e2e);
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

	// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \tPacket Send from %u.%u.%u.%u to %u.%u.%u.%u...\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24), 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));

	// Deal with special case SUPERMAN packets which we leave alone (after all, we made them)!
	if(spi->shdr)
	{
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
			case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:		// It's a Certificate Exchange
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tCertificate Exchange Packet.\n");
				spi->result = NF_ACCEPT;
				return FreeSupermanPacketInfo(spi);
				break;
			case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
				// printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - \t\tCertificate Exchange With Broadcast Key Packet.\n");
				spi->result = NF_ACCEPT;
				return FreeSupermanPacketInfo(spi);
				break;
			case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:
				printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen an SK Request, letting through.\n");
				break;
			case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:
				printk(KERN_INFO "SUPERMAN: Netfilter (POSTROUTING) - Seen an SK Response, letting through.\n");
				break;
		}
	}

	/*
	// Lookup the next hop and grab the security credentials
	if(spi->use_broadcast_key)
	{
		spi->next_hop_addr = spi->iph->daddr;
		spi->next_hop_security_details = spi->security_details;
		spi->has_next_hop_security_details = spi->has_security_details;
		spi->next_hop_security_flag = security_flag;
	}
	else
	{
		struct rtable* rt;
		struct dst_entry* dst;
		struct flowi4 fl4;
		memset(&fl4, 0, sizeof(fl4));
		fl4.daddr = spi->iph->daddr;
		fl4.flowi4_flags = 0x08;
	 	rt = ip_route_output_key(&init_net, &fl4);
	 	if (IS_ERR(rt))
		{
			printk(KERN_INFO "SUPERMAN: Netfilter - \tip_route_output_key error!\n");
			spi->has_next_hop_security_details = false;
		}

		// Do we have a gateway?
		if (rt->rt_gateway)
		{
			// Make sure we have the security credentials
			if(!GetSecurityTableEntry(rt->rt_gateway, &(spi->next_hop_security_details))
			{
				spi->result = NF_STOLEN;
				EnqueuePacket(spi, &hook_localout_post_sk_response);
				SendAuthenticatedSKRequestPacket(0, rt->rt_gateway);
			}
		}
		else
		{
			spi->next_hop_addr = spi->iph->daddr;
			spi->next_hop_security_details = spi->security_details;
			spi->has_next_hop_security_details = spi->has_security_details;
			spi->next_hop_security_flag = security_flag;
		}
	}
	*/

	return AddP2PSecurity(spi, &hook_postrouting_add_p2p);
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
