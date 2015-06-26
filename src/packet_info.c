#ifdef __KERNEL__

#include <linux/netdevice.h>
#include "packet_info.h"
#include "packet.h"
#include "security_table.h"

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

struct superman_packet_info* MallocSupermanPacketInfo(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct superman_packet_info* spi;
	spi = kmalloc(sizeof(struct superman_packet_info), GFP_ATOMIC);

	// Information provided by the hook function where the SPI originated.
	spi->hooknum = ops->hooknum;
	spi->skb = skb;
	spi->in = in;
	spi->out = out;
	spi->okfn = okfn;

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
	if(spi->hooknum == NF_INET_PRE_ROUTING || spi->hooknum == NF_INET_LOCAL_IN)
	{
		if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, spi->in);
		spi->addr = spi->iph->saddr;
	}
	else if(spi->hooknum == NF_INET_POST_ROUTING || spi->hooknum == NF_INET_LOCAL_OUT || spi->hooknum == NF_INET_FORWARD)
	{
		if_info_from_net_device(&spi->ifaddr, &spi->bcaddr, spi->out);
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

	// Security information
	switch(spi->addr_type)
	{
		case IS_MYADDR:
		case IS_LOOPBACK:
			spi->secure_packet = false;
			break;
		case IS_MULTICAST:
		case IS_BROADCAST:
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

	return spi;
}

unsigned int FreeSupermanPacketInfo(struct superman_packet_info* spi)
{
	unsigned int nf_result = spi->result;
	if(spi->use_callback && spi->result == NF_STOLEN && spi->skb != NULL)
	{
		spi->okfn(spi->skb);
	}
	else if(!spi->use_callback && spi->result == NF_STOLEN && spi->skb != NULL)
	{
		kfree_skb(spi->skb);
		spi->skb = NULL;
	}
	kfree(spi);
	return nf_result;
}


#endif
