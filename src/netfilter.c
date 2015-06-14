#ifdef __KERNEL__

#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>

#include "netfilter.h"
#include "packet.h"
#include "netlink.h"

unsigned int hook_prerouting(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int hook_localin(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int hook_forward(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int hook_localout(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int hook_postrouting(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

// Useful reference: http://phrack.org/issues/61/13.html

// After sanity checks, before routing decisions.
static struct nf_hook_ops nf_hook_prerouting = {
	.owner      	= THIS_MODULE,
	.hook 		= hook_prerouting,
	.hooknum 	= NF_IP_PRE_ROUTING,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};
// After routing decisions if packet is for this host.
static struct nf_hook_ops nf_hook_localin = {
	.owner      	= THIS_MODULE,
	.hook 		= hook_localin,
	.hooknum 	= NF_IP_LOCAL_IN,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};
// If the packet is destined for another interface.
static struct nf_hook_ops nf_hook_forward = {
	.owner      	= THIS_MODULE,
	.hook 		= hook_forward,
	.hooknum 	= NF_IP_FORWARD,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};
// For packets coming from local processes on their way out.
static struct nf_hook_ops nf_hook_localout = {
	.owner      	= THIS_MODULE,
	.hook 		= hook_localout,
	.hooknum 	= NF_IP_LOCAL_OUT,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};
// Just before outbound packets "hit the wire".
static struct nf_hook_ops nf_hook_postrouting = {
	.owner      	= THIS_MODULE,
	.hook 		= hook_postrouting,
	.hooknum 	= NF_IP_POST_ROUTING,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_FIRST
};


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

bool is_valid_ip_packet(struct sk_buff* skb)
{
	// Does this packet contain IP data?
	return skb && ip_hdr(skb);
}


bool is_superman_packet(struct sk_buff* skb)
{
	// Does this IPv4 packet contain superman payload?
	return (ip_hdr(skb)->protocol == SUPERMAN_PROTOCOL_NUM);

}

struct superman_header* get_superman_header(struct sk_buff *skb)
{
	return (struct superman_header*)skb_transport_header(skb);
}

// After sanity checks, before routing decisions.
unsigned int hook_prerouting(	const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	// Let non-IP packets through.
	if(!is_valid_ip_packet(skb))
		return NF_ACCEPT;

	// Deal with SUPERMAN packets!
	if(is_superman_packet(skb))
	{
		struct superman_header* shdr;
		void* payload;
		printk(KERN_INFO "SUPERMAN: Netfilter - Packet Received\n");

		shdr = get_superman_header(skb);
		payload = ((void*)shdr) + shdr->payload_len;
		switch(shdr->type)
		{
			case SUPERMAN_DISCOVERY_REQUEST_TYPE:			// It's a Discovery Request
				printk(KERN_INFO "SUPERMAN: Netfilter - Discovery Request Packet.\n");
				ReceivedSupermanDiscoveryRequest(ip_hdr(skb)->saddr, shdr->payload_len, payload);
				//SendCertificateRequest(skb);			// Respond with the Certificate Request
				return NF_DROP;					// Don't let a Discovery Request propogate higher up the stack
				break;

/*
			case SUPERMAN_CERTIFICATE_REQUEST_TYPE:			// It's a Certificate Request
				SendCertificateResponse(skb);			// Respond with a Certififcate Response				
				return NF_DROP;					// Don't let a Certificate Requestany propogate higher up the stack
				break;

			case SUPERMAN_CERTIFICATE_EXCHANGE_TYPE:		// It's a Certificate Exchange
				if(ReceiveCertificateExchange(skb))		// Process the incoming certificate, find out whether we need to request theirs
			// WRONG	SendCertificateRequest(skb);		// Request their certificate (if we don't have it already).
				return NF_DROP;					// Don't let a Certificate Exchange propogate higher up the stack
				break;

			// Everything from here should be encrypted / authenticatable

			case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:		// It's an Authenticated SK Request
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

			case SUPERMAN_SK_INVALIDATE_TYPE:
				InvalidateSK(skb);				// Invalidate the SK.
				return NF_ACCEPT;				// We let this propogate so that a broadcast can be routed.
				break;

			default:
				if(!HaveSK(skb)) {
					// Queue the packet
					SendAuthenticatedSKRequest(skb);
				}
				else {
					if(ReceiveP2PPacket(skb))		// Process the packet, stripping the superman header and unsecuring it's data.
						return NF_ACCEPT;		// Let the packet propogate
					else
						return NF_DROP;			// Drop the packet
				}
				break;
*/
		}
	}

	return NF_ACCEPT;
}

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

/*
The proc entry init and deinit functions deal with construction and destruction.
*/
void InitNetFilter(void)
{
	nf_register_hook(&nf_hook_prerouting);
	nf_register_hook(&nf_hook_localin);
	nf_register_hook(&nf_hook_forward);
	nf_register_hook(&nf_hook_localout);
	nf_register_hook(&nf_hook_postrouting);
}

void DeInitNetFilter(void)
{
	nf_unregister_hook(&nf_hook_prerouting);
	nf_unregister_hook(&nf_hook_localin);
	nf_unregister_hook(&nf_hook_forward);
	nf_unregister_hook(&nf_hook_localout);
	nf_unregister_hook(&nf_hook_postrouting);
}

#endif
