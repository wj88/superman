#ifdef __KERNEL__

#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>

#include "netfilter.h"
#include "packet_info.h"
#include "packet.h"
#include "netlink.h"
#include "security_table.h"
#include "security.h"
#include "processor.h"
#include "queue.h"

#define HOOK_DEF(func_name, ops_name, hook_num)																	\
unsigned int func_name(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));		\
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
//HOOK_DEF(hook_localin, nf_hook_localin, NF_IP_LOCAL_IN)
// If the packet is destined for another interface.
//HOOK_DEF(hook_forward, nf_hook_forward, NF_IP_FORWARD)
// For packets coming from local processes on their way out.
//HOOK_DEF(hook_localout, nf_hook_localout, NF_IP_LOCAL_OUT)
// Just before outbound packets "hit the wire".
//HOOK_DEF(hook_postrouting, nf_hook_postrouting, NF_IP_POST_ROUTING)


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



// EXAMPLE OF IP FILTERING - OUT-OF-DATE
/*
unsigned char *deny_ip = "\x7f\x00\x00\x01";	// 127.0.0.1
static int check_ip_packet(struct sk_buff *skb)
{
	// Grab the IP header
	struct iphdr* ip_header = ip_hdr(skb);

	if (ip_header->saddr == *(unsigned int *)deny_ip) { 
		return NF_DROP;
	}

	return NF_ACCEPT;
}
*/

// EXAMPLE OF TCP FILTERING - OUT-OF-DATE
/*
unsigned char *deny_port = "\x00\x19";	// port 25
static int check_tcp_packet(struct sk_buff *skb)
{
	// Grab the IP header
	struct iphdr* ip_header = ip_hdr(skb);

	// Be sure this is a TCP packet first
	if (ip_header->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}

	struct tcphdr* tcp_header = (struct tcphdr*)skb_transport_header(skb);

	// Now check the destination port
	if ((thead->dest) == *(unsigned short *)deny_port) {
		return NF_DROP;
	}

	return NF_ACCEPT;
}
*/

inline bool is_valid_ip_packet(struct sk_buff* skb)
{
	// Does this packet contain IP data?
	return skb && ip_hdr(skb);
}


unsigned int process_certificate_excahnge_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.


	__be16 certificate_len;
	unsigned char* certificate;

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(spi->shdr->payload_len >= sizeof(__be16))
	{
		certificate_len = *((__be16*) spi->payload);

		if(spi->shdr->payload_len >= sizeof(__be16) + certificate_len)
		{
			certificate = (unsigned char*)(spi->payload + sizeof(__be16));
			ReceivedSupermanCertificateExchange(spi->addr, (uint32_t)ntohs(certificate_len), certificate);
		}
	}

	spi->use_callback = false;
	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
	return FreeSupermanPacketInfo(spi);
}

unsigned int process_certificate_excahnge_with_broadcast_key_packet(struct superman_packet_info* spi)
{
	// NOTE: We need to free our spi.

	__be16 certificate_len;
	unsigned char* certificate;
	__be16 broadcast_key_len;
	unsigned char* broadcast_key;

	// Carefully, with plenty of bounds checking, extract the contents of the payload in the component parts.
	if(spi->shdr->payload_len >= sizeof(__be16))
	{
		certificate_len = *((__be16*) spi->payload);
		
		if(spi->shdr->payload_len >= sizeof(__be16) + certificate_len)
		{
			certificate = (unsigned char*)(spi->payload + sizeof(__be16));

			if(spi->shdr->payload_len >= sizeof(__be16) + certificate_len + sizeof(__be16))
			{
				broadcast_key_len = *((__be16*) (spi->payload + sizeof(__be16) + certificate_len));

				if(spi->shdr->payload_len >= sizeof(__be16) + certificate_len + sizeof(__be16) + broadcast_key_len)
				{
					broadcast_key = (unsigned char*)(spi->payload + sizeof(__be16) + certificate_len + sizeof(__be16));
					ReceivedSupermanCertificateExchangeWithBroadcastKey(spi->addr, (uint32_t)ntohs(certificate_len), certificate, (uint32_t)ntohs(broadcast_key_len), broadcast_key);
				}
			}
		}
	}

	if(spi->result != NF_STOLEN) spi->result = NF_DROP;

	// Cleanup the SPI!
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
					return process_certificate_excahnge_packet(spi);
					break;

				case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
					return process_certificate_excahnge_with_broadcast_key_packet(spi);
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
					return RemoveE2ESecurity(spi, &hook_prerouting_removed_e2e);
					break;

				case SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE:		// It's a Certificate Exchange With Broadcast Key
					spi->security_flag = 2;
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

// After sanity checks, before routing decisions.
unsigned int hook_prerouting(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct superman_packet_info* spi;

	// Let non-IP packets through.
	if(!is_valid_ip_packet(skb))
		return NF_ACCEPT;

	printk(KERN_INFO "SUPERMAN: Netfilter - Packet Received\n");

	// Construct a new SPI to handle this packet.
	spi = MallocSupermanPacketInfo(ops, skb, in, out, okfn);

	// Deal with special case unencapsulated SUPERMAN packets which are not secured!
	if(spi->shdr)
	{
		if(spi->shdr->payload_len != skb->data_len - (skb_transport_offset(skb) + sizeof(struct superman_header)))
		{
			printk(KERN_INFO "SUPERMAN: Netfilter - Superman packet failed initial basic sanity check.\n");
			spi->result = NF_DROP;
			return FreeSupermanPacketInfo(spi);
		}

		switch(spi->shdr->type)
		{
			case SUPERMAN_DISCOVERY_REQUEST_TYPE:			// It's a Discovery Request
				printk(KERN_INFO "SUPERMAN: Netfilter - Discovery Request Packet.\n");
				ReceivedSupermanDiscoveryRequest(spi->addr, spi->shdr->payload_len, spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
				break;

			case SUPERMAN_CERTIFICATE_REQUEST_TYPE:			// It's a Certificate Request
				printk(KERN_INFO "SUPERMAN: Netfilter - Certificate Request Packet.\n");
				ReceivedSupermanCertificateRequest(spi->addr, spi->shdr->payload_len, spi->payload, spi->shdr->timestamp, spi->skb->skb_iif);
				spi->result = NF_DROP;
				return FreeSupermanPacketInfo(spi);
				break;
		}
	}

	// Do we have the required security details of the source to remove
	// the P2P... if not we must queue up the packet and request them.
	if(!spi->has_security_details)
	{
		// If it the broadcast key we don't have, ditch the packet.
		if(spi->use_broadcast_key)
		{
			spi->result = NF_DROP;
			return FreeSupermanPacketInfo(spi);
		}
		// Otherwise queue the packet and send an SK request.
		else
		{
			spi->result = NF_STOLEN;
			EnqueuePacket(spi, &hook_prerouting_post_sk_response);
			SendAuthenticatedSKRequest(spi->addr);
			return spi->result;
		}
	}

	// For all other packet types, they must pass the hmac check!
	// NOTE: The callback becomes responsible for clearing up the SPI.
	return RemoveP2PSecurity(spi, &hook_prerouting_removed_p2p);
}

/*
// After sanity checks, before routing decisions.
unsigned int hook_localin(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	//if(is_valid_ip_packet(skb) && is_superman_packet(skb))
		return NF_ACCEPT;
	//else
	//	return NF_DROP;           	// Drop ALL packets
}

// After sanity checks, before routing decisions.
unsigned int hook_forward(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	//if(is_valid_ip_packet(skb) && is_superman_packet(skb))
		return NF_ACCEPT;
	//else
	//	return NF_DROP;           	// Drop ALL packets
}

// After sanity checks, before routing decisions.
unsigned int hook_localout(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	//if(is_valid_ip_packet(skb) && is_superman_packet(skb))
		return NF_ACCEPT;
	//else
	//	return NF_DROP;           	// Drop ALL packets
}

// After sanity checks, before routing decisions.
unsigned int hook_postrouting(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	//if(is_valid_ip_packet(skb) && is_superman_packet(skb))
		return NF_ACCEPT;
	//else
	//	return NF_DROP;           	// Drop ALL packets
}
*/

/*
The proc entry init and deinit functions deal with construction and destruction.
*/
void InitNetFilter(void)
{
	nf_register_hook(&nf_hook_prerouting);
/*
	nf_register_hook(&nf_hook_localin);
	nf_register_hook(&nf_hook_forward);
	nf_register_hook(&nf_hook_localout);
	nf_register_hook(&nf_hook_postrouting);
*/
}

void DeInitNetFilter(void)
{
	nf_unregister_hook(&nf_hook_prerouting);
/*
	nf_unregister_hook(&nf_hook_localin);
	nf_unregister_hook(&nf_hook_forward);
	nf_unregister_hook(&nf_hook_localout);
	nf_unregister_hook(&nf_hook_postrouting);
*/
}

#endif
