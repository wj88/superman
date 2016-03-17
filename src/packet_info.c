#ifdef __KERNEL__

#include <linux/netdevice.h>
#include "packet_info.h"
#include "packet.h"
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

// A useful function shamelessly stolen from the AODV-UU implementation.
static inline int if_info_from_net_device(struct in_addr *addr, struct in_addr *baddr, const struct net_device *dev)
{
	struct in_device *indev;
	bool found = false;

	// Hold a reference to the device to prevent it from being freed.
	indev = in_dev_get(dev);
	if (indev)
	{
		struct in_ifaddr **ifap;
		struct in_ifaddr *ifa;
		bool found = false;

		// Search through the list for a matching device name.
		
		for (ifap = &indev->ifa_list; (ifa = *ifap) != NULL; ifap = &ifa->ifa_next)
		{
			if (!strcmp(dev->name, ifa->ifa_label))
			{
				found = true;
				break;
			}
		}

		if(found)
		{
			if (addr)
				addr->s_addr = ifa->ifa_address;
			if (baddr)
				baddr->s_addr = ifa->ifa_broadcast;
		}

		// Release our reference to the device.
		in_dev_put(indev);
	}

	return found;
}

struct superman_packet_info* MallocSupermanPacketInfo(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct superman_packet_info* spi;
	++superman_packet_info_count;
	++superman_packet_info_id_counter;
	// printk(KERN_INFO "SUPERMAN: packet_info: \tAllocating a new superman_packet_info (%u current allocated, id: %u)...\n", superman_packet_info_count, superman_packet_info_id_counter);

	spi = kmalloc(sizeof(struct superman_packet_info), GFP_ATOMIC);
	if(spi == NULL)
	{
		printk(KERN_INFO "SUPERMAN: packet_info: \t\tFailed to allocate a new superman_packet_info.\n");
		return NULL;
	}

	// Information provided by the hook function where the SPI originated.
	spi->ops = ops;
	spi->skb = skb;
	spi->state = state;

	// Useful pointers to the relevant parts of the packet.
	spi->iph = ip_hdr(skb);				// We can grab the IP header
	if(!is_superman_packet(skb))			// We can only get this at local in/out - routing may have added additional headers.
	{
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
	if(spi->ops != NULL && (spi->ops->hooknum == NF_INET_PRE_ROUTING || spi->ops->hooknum == NF_INET_LOCAL_IN))
	{
		if(spi->state->in != NULL)
			if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, spi->state->in);
		spi->addr = spi->iph->saddr;
	}
	else if(spi->ops != NULL && (spi->ops->hooknum == NF_INET_POST_ROUTING || spi->ops->hooknum == NF_INET_LOCAL_OUT || spi->ops->hooknum == NF_INET_FORWARD))
	{
		if(spi->state->out != NULL)
			if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, spi->state->out);
		spi->addr = spi->iph->daddr;
	}
	else
		spi->addr = 0;

	// Address information about the origin/destination of this packet.	
	if(spi->ifaddr.s_addr == spi->addr)
		spi->addr_type = IS_MYADDR;
	else if(ipv4_is_loopback(spi->addr))
		spi->addr_type = IS_LOOPBACK;
	else if(ipv4_is_multicast(spi->addr) || ipv4_is_local_multicast(spi->addr))
		spi->addr_type = IS_MULTICAST;
	else if(ipv4_is_lbcast(spi->addr) || spi->addr == spi->bcaddr.s_addr)
		spi->addr_type = IS_BROADCAST;
	else
		spi->addr_type = IS_OTHER;

	// Deal with the special case of SK requests
	if(spi->shdr != NULL && spi->shdr->type == SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE)
		spi->addr_type = IS_BROADCAST;

	// Security information
	switch(spi->addr_type)
	{
		case IS_MYADDR:
		case IS_LOOPBACK:
			// printk(KERN_INFO "SUPERMAN: packet_info - \tPacket is from me or is a loopback packet.\n");
#ifdef ENCRYPT_LOCAL
			spi->secure_packet = true;
#else
			spi->secure_packet = false;
#endif
			break;
		case IS_MULTICAST:
		case IS_BROADCAST:
			// printk(KERN_INFO "SUPERMAN: packet_info - \tPacket is a broadcast or multicast packet.\n");
			spi->secure_packet = true;
			spi->use_broadcast_key = true;
			break;
		default:
			spi->secure_packet = true;
			spi->use_broadcast_key = false;
			break;
	}
	spi->security_flag = 3;

	// If we should use the broadcast key and we don't have one. 
	if(spi->use_broadcast_key && (!GetSecurityTableEntry(INADDR_BROADCAST, &(spi->security_details))))
		spi->has_security_details = false;
	// If it isn't a broadcast packet and we don't have the targets key.
	else if(!spi->use_broadcast_key && (!GetSecurityTableEntry(spi->addr, &(spi->security_details))))
		spi->has_security_details = false;
	else
		spi->has_security_details = true;

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
	// printk(KERN_INFO "SUPERMAN: packet_info: \tFreeing superman_packet_info (%u current allocated, id: %u)...\n", superman_packet_info_count, spi->id);

	if(spi->use_callback && spi->result == NF_STOLEN && spi->skb != NULL)
	{
		if(spi->state != NULL && spi->state->okfn != NULL)
		{
			printk(KERN_INFO "SUPERMAN: packet_info: \tCalling the OK function because we stole the packet...\n");
			spi->state->okfn(spi->state->sk, spi->skb);
		}
	}
	else if(!spi->use_callback && spi->result == NF_STOLEN && spi->skb != NULL)
	{
		kfree_skb(spi->skb);
		spi->skb = NULL;
	}
	// else if(spi->result == NF_ACCEPT)
	// 	printk(KERN_INFO "SUPERMAN: packet_info: \tAccepting the packet...\n");
	// else if(spi->result == NF_DROP)
	// 	printk(KERN_INFO "SUPERMAN: packet_info: \tDropping the packet...\n");
	// else if(spi->result == NF_STOLEN)
	// 	printk(KERN_INFO "SUPERMAN: packet_info: \tStealing the packet...\n");

	kfree(spi);
	return nf_result;
}


#endif
