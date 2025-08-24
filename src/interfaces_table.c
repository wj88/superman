#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include "interfaces_table.h"

struct interfaces_table* GetInterfacesTable()
{
	struct superman_net* snet = GetSupermanNet();
	return (struct interfaces_table*)snet->interfaces_table;
}

#define list_is_first(e) (&e->l == interfaces_table_head.next)

// rwlock_t* GetInterfacesTableLock(void)
// {
// 	struct interfaces_table* it = GetInterfacesTable();
// 	if(it)
// 		return NULL;

// 	return &it->interfaces_table_lock;
// }

// struct list_head* GetInterfacesTable(void)
// {
// 	struct interfaces_table* it = GetInterfacesTable();
// 	if(it)
// 		return NULL;

// 	return &it->interfaces_table_head;
// }

// uint32_t GetInterfacesCount(void)
// {
// 	struct interfaces_table* it = GetInterfacesTable();
// 	if(it)
// 		return NULL;

// 	return it->interfaces_table_total;
// }

static inline void __interfaces_table_flush(struct interfaces_table* it)
{
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &it->interfaces_table_head) {
		struct interfaces_table_entry *e = (struct interfaces_table_entry *)pos;
		list_del(&e->l);
		it->interfaces_table_total--;
		kfree(e);
	}
}

static inline bool __interfaces_table_add(struct interfaces_table* it, struct interfaces_table_entry *e)
{
	if (list_empty(&it->interfaces_table_head)) {
		list_add(&e->l, &it->interfaces_table_head);
	}
	else
	{
		list_add_tail(&e->l, &it->interfaces_table_head);
	}
	return true;
}

static inline struct interfaces_table_entry *__interfaces_table_find(struct interfaces_table* it, uint32_t ifindex)
{
	struct list_head *pos;

	list_for_each(pos, &it->interfaces_table_head) {
		struct interfaces_table_entry *e = (struct interfaces_table_entry *)pos;

		if (e->ifindex == ifindex)
			return e;
	}
	return NULL;
}

static inline bool __interfaces_table_del(struct interfaces_table* it, struct interfaces_table_entry *e)
{
	if (e == NULL)
		return false;

	list_del(&e->l);

	it->interfaces_table_total--;

	return true;
}

bool RemoveInterfacesTableEntry(uint32_t ifindex)
{
	struct interfaces_table* it	= GetInterfacesTable();
	if(!it)
		return false;

	struct interfaces_table_entry *e;

	write_lock_bh(&it->interfaces_table_lock);

	if ((e = __interfaces_table_find(it, ifindex)) && __interfaces_table_del(it, e))
	{
		kfree(e);
		write_unlock_bh(&it->interfaces_table_lock);
		return true;
	}

	write_unlock_bh(&it->interfaces_table_lock);
	return false;
}

bool HasInterfacesTableEntry(uint32_t ifindex)
{
	struct interfaces_table* it	= GetInterfacesTable();
	if(!it)
		return false;

	struct interfaces_table_entry* entry;
	read_lock_bh(&it->interfaces_table_lock);
	entry = __interfaces_table_find(it, ifindex);
	read_unlock_bh(&it->interfaces_table_lock);
	return entry != NULL;
}

bool AddInterfacesTableEntry(uint32_t ifindex)
{
	if(HasInterfacesTableEntry(ifindex))
	{
		return true;
	}
	else
	{
		struct interfaces_table* it	= GetInterfacesTable();
		if(!it)
			return false;


		struct interfaces_table_entry *e;
		bool r = false;

		// printk(KERN_ERR "SUPERMAN: interfaces_table - \t\tCreating a new entry...\n");
		e = kmalloc(sizeof(struct interfaces_table_entry), GFP_ATOMIC);
		if (e == NULL) {
			printk(KERN_ERR "interfaces_table: \t\t\t\"Out Of Memory\" in AddInterfacesTableEntry\n");
			return false;
		}
		memset(e, 0, sizeof(struct interfaces_table_entry));
		//e->net = net;
		e->ifindex = ifindex;

		write_lock_bh(&it->interfaces_table_lock);
		r = __interfaces_table_add(it, e);
		if(r)
			it->interfaces_table_total++;
		write_unlock_bh(&it->interfaces_table_lock);

		if(!r)
			kfree(e);

		return r;
	}
}

uint32_t GetInterfaceFromName(char* ifname)
{
	uint32_t ifindex = -1;
	struct net *net = GetNet();
	if(net)
	{
		struct net_device* dev;

		// Find the index
		dev = dev_get_by_name(net, ifname);
		if(dev)
		{
			ifindex = dev->ifindex;
			dev_put(dev);
		}

		put_net(net);
	}
	return ifindex;
}

int interfaces_table_info_proc_show(struct seq_file *m, void *v)
{
	struct net *net = GetNet();
	if(net)
	{
		struct interfaces_table* it	= GetInterfacesTable();
		if(!it)
			return false;

		read_lock_bh(&it->interfaces_table_lock);
		read_lock(&dev_base_lock);

		seq_printf(m, "%-6s %-20s %-16s %-16s %-10s\n", "Index", "Name", "Address", "Broadcast", "Secured");

		struct net_device *dev;
		for_each_netdev(net, dev) {
			bool hasEntry = (__interfaces_table_find(it, dev->ifindex) != NULL);
			char addr[16] = "";
			char baddr[16] = "";
			struct in_device *indev;

			// Hold a reference to the device to prevent it from being freed.
			indev = in_dev_get(dev);
			if (indev)
			{
				struct in_ifaddr **ifap;
				struct in_ifaddr *ifa;

				// Search through the list for a matching device name.
				for (ifap = &indev->ifa_list; (ifa = *ifap) != NULL; ifap = &ifa->ifa_next)
				{
					if (!strcmp(dev->name, ifa->ifa_label))
					{
						sprintf(addr, "%u.%u.%u.%u", (0x0ff & ifa->ifa_address), (0x0ff & (ifa->ifa_address >> 8)), (0x0ff & (ifa->ifa_address >> 16)), (0x0ff & (ifa->ifa_address >> 24)));
						sprintf(baddr, "%u.%u.%u.%u", (0x0ff & ifa->ifa_broadcast), (0x0ff & (ifa->ifa_broadcast >> 8)), (0x0ff & (ifa->ifa_broadcast >> 16)), (0x0ff & (ifa->ifa_broadcast >> 24)));
						break;
					}
				}

				// Release our reference to the device.
				in_dev_put(indev);
			}

			seq_printf(m, "%-6d %-20s %-16s %-16s %-10s\n", dev->ifindex, dev->name, addr, baddr, (hasEntry ? "SUPERMAN" : "no"));
		}

		read_unlock_bh(&it->interfaces_table_lock);
		read_unlock(&dev_base_lock);

		put_net(net);
	}
	return 0;
}

bool InitInterfacesTable(struct superman_net* snet)
{
	snet->interfaces_table = kmalloc(sizeof(struct interfaces_table), GFP_KERNEL);
	if(!snet->interfaces_table)
	{
		printk(KERN_WARNING "SUPERMAN interfaces_table: unable to create the interfaces_table.\n");
		return false;
	}
	struct interfaces_table* it = (struct interfaces_table*)snet->interfaces_table;

	INIT_LIST_HEAD(&it->interfaces_table_head);
	it->interfaces_table_lock = __RW_LOCK_UNLOCKED(it->interfaces_table_lock);
	it->interfaces_table_total = 0;
	return true;
}

void DeInitInterfacesTable(struct superman_net* snet)
{
	struct interfaces_table* it = snet->interfaces_table;
	if(it)
	{
		write_lock_bh(&it->interfaces_table_lock);
		__interfaces_table_flush(it);
		write_unlock_bh(&it->interfaces_table_lock);
		
		kfree(snet->interfaces_table);
		snet->interfaces_table = NULL;
	}
}

#endif
