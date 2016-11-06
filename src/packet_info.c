#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <net/route.h>
#include "packet_info.h"
#include "packet.h"
#include "security.h"
#include "security_table.h"

static unsigned int superman_packet_info_count = 0;
static unsigned int superman_packet_info_id_counter = 0;

/*
uint16_t GetNextTimestampFromSupermanPacketInfo(struct superman_packet_info* spi)
{
	if(spi->security_details != NULL)
	{
		if(spi->security_details->timestamp == 0xFFFF) spi->security_details->timestamp = 0;
		spi->security_details->timestamp++;
		return spi->security_details->timestamp;
	}
	return 0;
}
*/

void RefreshSupermanPacketInfo(struct superman_packet_info* spi)
{
	//printk(KERN_INFO "SUPERMAN: packet_info: \tRefreshing superman_packet_info (id: %u, %u current allocated)...\n", spi->id, superman_packet_info_count);

	// If we're dealing with LOCAL_OUT or LOCAL_IN we'll be needing the E2E security details.
	// Also, if we in pre-routing but have a SK request package, we zip off the e2e at that point.
	if(	spi->hook == NF_INET_LOCAL_OUT ||
		spi->hook == NF_INET_LOCAL_IN ||
		(spi->hook == NF_INET_PRE_ROUTING && spi->shdr && (spi->shdr->type == SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE || spi->shdr->type == SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE))
	)
	{
		// If we should use the broadcast key and we don't have one.
		if(spi->e2e_use_broadcast_key && ((!GetSecurityTableEntry(INADDR_BROADCAST, &(spi->e2e_security_details))) || spi->e2e_security_details->flag < SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED))
		{
			printk(KERN_INFO "SUPERMAN: packet_info - \tNo broadcast key.\n");
			spi->e2e_has_security_details = false;
		}
		// If it isn't a broadcast packet and we don't have the targets key.
		else if(!spi->e2e_use_broadcast_key && ((!GetSecurityTableEntry(spi->e2e_addr, &(spi->e2e_security_details))) || spi->e2e_security_details->flag == SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE))
		{
			printk(KERN_INFO "SUPERMAN: packet_info: e2e no security entry for %u.%u.%u.%u.\n", 0x0ff & spi->e2e_addr, 0x0ff & (spi->e2e_addr >> 8), 0x0ff & (spi->e2e_addr >> 16), 0x0ff & (spi->e2e_addr >> 24));
			spi->e2e_has_security_details = false;
		}
		else
		{
			if(spi->shdr && (spi->shdr->type == SUPERMAN_CERTIFICATE_EXCHANGE_TYPE || spi->shdr->type == SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE))
				spi->e2e_has_security_details = spi->e2e_security_details->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED;
			else
				spi->e2e_has_security_details = spi->e2e_security_details->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED;
			//printk(KERN_INFO "SUPERMAN: packet_info: e2e sec for %u.%u.%u.%u, flag = %d, sec = %s.\n", 0x0ff & spi->e2e_addr, 0x0ff & (spi->e2e_addr >> 8), 0x0ff & (spi->e2e_addr >> 16), 0x0ff & (spi->e2e_addr >> 24), spi->e2e_security_details->flag, (spi->e2e_has_security_details ? "true" : "false"));
		}
	}

	// If we're dealing with PRE_ROUTING OR POST_ROUTING we'll be needing the P2P security details.
	if(spi->hook == NF_INET_POST_ROUTING || spi->hook == NF_INET_PRE_ROUTING)
	{
		spi->p2p_our_addr = htonl(0);
		spi->p2p_neighbour_addr = htonl(0);

		// Lookup the next hop and grab the security credentials
		if(spi->p2p_use_broadcast_key)
		{
			spi->p2p_has_security_details = GetSecurityTableEntry(INADDR_BROADCAST, &(spi->p2p_security_details));
		}
		else
		{
			// If the packet is on it's way out...
			if(spi->hook == NF_INET_POST_ROUTING)
			{
				// We need the next hops IP address and security credentials.
				struct rtable* rt;
				struct flowi4 fl4;
				memset(&fl4, 0, sizeof(fl4));
				fl4.daddr = spi->e2e_addr;
				fl4.flowi4_flags = 0x08;
			 	rt = ip_route_output_key(&init_net, &fl4);
			 	if (IS_ERR(rt))
				{
					printk(KERN_INFO "SUPERMAN: Netfilter - \tip_route_output_key error!\n");
					spi->p2p_has_security_details = false;
				}

				// Do we have a gateway?
				if (rt->rt_gateway)
					spi->p2p_neighbour_addr = rt->rt_gateway;
				else
					spi->p2p_neighbour_addr = spi->e2e_addr;

				spi->p2p_our_addr = inet_select_addr(rt->dst.dev, spi->p2p_neighbour_addr, RT_SCOPE_UNIVERSE);
			}

			// If the packet is on it's way in...
			if(spi->hook == NF_INET_PRE_ROUTING)
			{
				// We need the the last hops IP address and security credentials.
				spi->p2p_neighbour_addr = spi->shdr->last_addr;
				spi->p2p_our_addr = spi->ifaddr;
			}

			if(!GetSecurityTableEntry(spi->p2p_neighbour_addr, &(spi->p2p_security_details)))
			{
				printk(KERN_INFO "SUPERMAN: packet_info: p2p no security entry for neighbour %u.%u.%u.%u.\n", 0x0ff & spi->p2p_neighbour_addr, 0x0ff & (spi->p2p_neighbour_addr >> 8), 0x0ff & (spi->p2p_neighbour_addr >> 16), 0x0ff & (spi->p2p_neighbour_addr >> 24));
				spi->p2p_has_security_details = false;
			}
			else
			{
				if(spi->shdr && (spi->shdr->type == SUPERMAN_CERTIFICATE_EXCHANGE_TYPE || spi->shdr->type == SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE))
					spi->p2p_has_security_details = spi->p2p_security_details->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED;
				else
					spi->p2p_has_security_details = spi->p2p_security_details->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED;
				//printk(KERN_INFO "SUPERMAN: packet_info: p2p sec for neighbour %u.%u.%u.%u, flag = %d, sec = %s.\n", 0x0ff & spi->p2p_neighbour_addr, 0x0ff & (spi->p2p_neighbour_addr >> 8), 0x0ff & (spi->p2p_neighbour_addr >> 16), 0x0ff & (spi->p2p_neighbour_addr >> 24), spi->p2p_security_details->flag, (spi->p2p_has_security_details ? "true" : "false"));
			}

		}
	}
}

struct superman_packet_info* MallocSupermanPacketInfo(struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	++superman_packet_info_count;
	++superman_packet_info_id_counter;
	//printk(KERN_INFO "SUPERMAN: packet_info: \tAllocating a new superman_packet_info (id: %u, %u current allocated)...\n", superman_packet_info_id_counter, superman_packet_info_count);

	spi = kmalloc(sizeof(struct superman_packet_info), GFP_ATOMIC);
	if(spi == NULL)
	{
		printk(KERN_ERR "SUPERMAN: packet_info: \t\tFailed to allocate a new superman_packet_info.\n");
		return NULL;
	}

	// Information provided by the hook function where the SPI originated.
	spi->skb = skb;
	spi->hook = (state != NULL ? state->hook : -1);
	spi->okfn = (state != NULL ? state->okfn : NULL);
	spi->sk = (state != NULL ? state->sk : NULL);
	spi->net = (state != NULL ? state->net : NULL);

	// Packet arrival isn't always linear which breaks things. Fix that here.
	skb_linearize(skb);

	//printk(KERN_INFO "SUPERMAN: packet_info: IP Offset: %d, Transport Offset: %d, Transport*: %lu.\n", skb_network_offset(skb), skb_transport_offset(skb), (unsigned long)(skb_transport_header(skb)-skb_network_header(skb)));
	//printk(KERN_INFO "SUPERMAN: packet_info: IP Header:\n");
	//dump_bytes(skb_network_header(skb), skb_network_header_len(skb));
	//printk(KERN_INFO "SUPERMAN: packet_info: Transport Header:\n");
	//dump_bytes(skb_transport_header(skb), sizeof(struct superman_header));

	// Useful pointers to the relevant parts of the packet.
	spi->iph = (struct iphdr*)skb_network_header(skb);	// We can grab the IP header

	if(!is_superman_packet(skb))				// We can only get this at local in/out - routing may have added additional headers.
	{
		//printk(KERN_INFO "SUPERMAN: packet_info: \t\tNot a SUPERMAN packet.\n");
		spi->shdr = NULL;
		spi->payload = NULL;
	}
	else						// The exception to the last comment is when a packet was injected into post routing.
	{
		spi->shdr = get_superman_header(skb);
		spi->payload = ((void*)spi->shdr) + sizeof(struct superman_header);
	}

	// Address information about the origin/destination of this packet.
	memset(&spi->ifaddr, 0, sizeof(struct in_addr));
	memset(&spi->bcaddr, 0, sizeof(struct in_addr));
	if(state != NULL && (spi->hook == NF_INET_PRE_ROUTING || spi->hook == NF_INET_LOCAL_IN))
	{
		if(state->in != NULL)
			if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, state->in);
		spi->e2e_addr = spi->iph->saddr;
	}
	else if(state != NULL && (spi->hook == NF_INET_POST_ROUTING || spi->hook == NF_INET_LOCAL_OUT || spi->hook == NF_INET_FORWARD))
	{
		if(state->out != NULL)
			if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, state->out);
		spi->e2e_addr = spi->iph->daddr;
	}
	// If all else fails, we probably generated this packet ourselves.
	else
	{
		spi->e2e_addr = htonl(0);

		/*
		if(spi->state != NULL)
		{
			printk(KERN_INFO "SUPERMAN: packet_info - \tspi->state->hooknum == %u\n", spi->state->hook);
			printk(KERN_INFO "SUPERMAN: packet_info - \tspi->e2e_addr  == %u.%u.%u.%u\n", 0x0ff & spi->e2e_addr, 0x0ff & (spi->e2e_addr >> 8), 0x0ff & (spi->e2e_addr >> 16), 0x0ff & (spi->e2e_addr >> 24));
			printk(KERN_INFO "SUPERMAN: packet_info - \tspi->iph->saddr == %u.%u.%u.%u\n", 0x0ff & spi->iph->saddr, 0x0ff & (spi->iph->saddr >> 8), 0x0ff & (spi->iph->saddr >> 16), 0x0ff & (spi->iph->saddr >> 24));
			printk(KERN_INFO "SUPERMAN: packet_info - \tspi->iph->daddr == %u.%u.%u.%u\n", 0x0ff & spi->iph->daddr, 0x0ff & (spi->iph->daddr >> 8), 0x0ff & (spi->iph->daddr >> 16), 0x0ff & (spi->iph->daddr >> 24));
		}
		else
			printk(KERN_INFO "SUPERMAN: packet_info - \tspi->state == NULL\n");
		*/
	}

	// Address information about the origin/destination of this packet.
	if(spi->ifaddr == spi->e2e_addr)
		spi->addr_type = IS_MYADDR;
	else if(ipv4_is_loopback(spi->e2e_addr))
		spi->addr_type = IS_LOOPBACK;
	else if(ipv4_is_multicast(spi->e2e_addr) || ipv4_is_local_multicast(spi->e2e_addr))
		spi->addr_type = IS_MULTICAST;
	else if(ipv4_is_lbcast(spi->e2e_addr) || spi->e2e_addr == spi->bcaddr)
		spi->addr_type = IS_BROADCAST;
	else
		spi->addr_type = IS_OTHER;

	{
		// Security information
		switch(spi->addr_type)
		{
			case IS_MYADDR:
			case IS_LOOPBACK:
				// printk(KERN_INFO "SUPERMAN: packet_info - \tPacket is from me or is a loopback packet.\n");
	#ifdef ENCRYPT_LOCAL
				spi->e2e_secure_packet = true;
				spi->p2p_secure_packet = true;
	#else
				spi->e2e_secure_packet = false;
				spi->p2p_secure_packet = false;
	#endif
				spi->e2e_use_broadcast_key = false;
				spi->p2p_use_broadcast_key = false;
				break;
			case IS_MULTICAST:
			case IS_BROADCAST:
				// printk(KERN_INFO "SUPERMAN: packet_info - \tPacket is a broadcast or multicast packet.\n");
				spi->e2e_secure_packet = true;
				spi->p2p_secure_packet = true;
				spi->e2e_use_broadcast_key = true;
				spi->p2p_use_broadcast_key = true;
				break;
			default:
				spi->e2e_secure_packet = true;
				spi->e2e_use_broadcast_key = false;
				spi->p2p_secure_packet = true;
				spi->p2p_use_broadcast_key = false;
				break;
		}
	}

	// Deal with the special case of SK requests
	if(spi->shdr != NULL)
	{
		switch(spi->shdr->type)
		{
			// The only insecured packets types allowed when SUPERMAN is enabled.
			case SUPERMAN_DISCOVERY_REQUEST_TYPE:
			case SUPERMAN_CERTIFICATE_REQUEST_TYPE:
				spi->e2e_secure_packet = false;
				spi->p2p_secure_packet = false;
				break;
			// For certain packet types, we use the broadcast key for e2e (although not for p2p)
			case SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE:
			case SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE:
			case SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE:
			case SUPERMAN_SK_INVALIDATE_TYPE:
				spi->e2e_use_broadcast_key = true;
				break;
		}
	}

	// Deal with the case where we were the source
	//if(spi->e2e_addr == htonl(0))
	//	spi->p2p_secure_packet = false;

	RefreshSupermanPacketInfo(spi);

	// The result (one of the NF_* values)
	spi->result = NF_DROP;
	spi->use_callback = false;

	// Temporary storage locations for use by any phase of the process as appropriate.
	spi->arg = NULL;
	spi->tmp = NULL;

	// Temporary spi identifier
	spi->id = superman_packet_info_id_counter;

	return spi;
}

unsigned int FreeSupermanPacketInfo(struct superman_packet_info* spi)
{
	unsigned int nf_result = spi->result;
	superman_packet_info_count--;
	//printk(KERN_INFO "SUPERMAN: packet_info: \tFreeing superman_packet_info (id: %u, %u current allocated)...\n", spi->id, superman_packet_info_count);

	if(spi->result == NF_STOLEN)
	{
		//printk(KERN_INFO "SUPERMAN: packet_info: \tStolen packet...\n");
		if(spi->skb == NULL)
		{
			printk(KERN_INFO "SUPERMAN: packet_info: \tskb == NULL!\n");
		}
		else
		{
			if(spi->use_callback)
			{
				//printk(KERN_INFO "SUPERMAN: packet_info: \tCalling the OK function because we stole the packet...\n");
				spi->okfn(spi->net, spi->sk, spi->skb);
			}
			else
			{
				//printk(KERN_INFO "SUPERMAN: packet_info: \tFreeing the sk_buff...\n");
				kfree_skb(spi->skb);
				spi->skb = NULL;
			}
		}
	}
	/*
	else if(spi->result == NF_ACCEPT)
		printk(KERN_INFO "SUPERMAN: packet_info: \tAccepting the packet...\n");
	else if(spi->result == NF_DROP)
		printk(KERN_INFO "SUPERMAN: packet_info: \tDropping the packet...\n");
	else if(spi->result == NF_STOLEN)
		printk(KERN_INFO "SUPERMAN: packet_info: \tStealing the packet...\n");
	*/

	kfree(spi);
	return nf_result;
}


#endif
