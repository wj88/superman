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

static unsigned int interfaces_table_len;
static rwlock_t interfaces_table_lock = __RW_LOCK_UNLOCKED(interfaces_table_lock);
static LIST_HEAD(interfaces_table_head);

#define list_is_first(e) (&e->l == interfaces_table_head.next)

rwlock_t* GetInterfacesTableLock(void)
{
	return &interfaces_table_lock;
}

struct list_head* GetInterfacesTable(void)
{
	return &interfaces_table_head;
}

uint32_t GetInterfacesCount(void)
{
	return interfaces_table_len;
}

static inline void __interfaces_table_flush(void)
{
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &interfaces_table_head) {
		struct interfaces_table_entry *e = (struct interfaces_table_entry *)pos;
		list_del(&e->l);
		interfaces_table_len--;
		kfree(e);
	}
}

static inline bool __interfaces_table_add(struct interfaces_table_entry *e)
{
	if (list_empty(&interfaces_table_head)) {
		list_add(&e->l, &interfaces_table_head);
	}
	else
	{
		list_add_tail(&e->l, &interfaces_table_head);
	}
	return true;
}

static inline struct interfaces_table_entry *__interfaces_table_find(uint32_t ifindex)
{
	struct list_head *pos;

	list_for_each(pos, &interfaces_table_head) {
		struct interfaces_table_entry *e = (struct interfaces_table_entry *)pos;

		if (e->ifindex == ifindex)
			return e;
	}
	return NULL;
}

static inline bool __interfaces_table_del(struct interfaces_table_entry *e)
{
	if (e == NULL)
		return false;

	list_del(&e->l);

	interfaces_table_len--;

	return true;
}

bool RemoveInterfacesTableEntry(uint32_t ifindex)
{
	struct interfaces_table_entry *e;

	write_lock_bh(&interfaces_table_lock);

	if ((e = __interfaces_table_find(ifindex)) && __interfaces_table_del(e))
	{
		kfree(e);
		write_unlock_bh(&interfaces_table_lock);
		return true;
	}
	
	write_unlock_bh(&interfaces_table_lock);
	return false;
}

bool RemoveInterfacesTableEntryByName(char* ifname)
{
	struct net_device* dev;
	uint32_t ifindex;

	// Find the index
	dev = dev_get_by_name(&init_net, ifname);
	if(dev == NULL) return false;
	ifindex = dev->ifindex;
	dev_put(dev);

	return RemoveInterfacesTableEntry(ifindex);
}

bool HasInterfacesTableEntry(uint32_t ifindex)
{
	struct interfaces_table_entry* entry;
	read_lock_bh(&interfaces_table_lock);
	entry = __interfaces_table_find(ifindex);
	read_unlock_bh(&interfaces_table_lock);
	return entry != NULL;
}

bool AddInterfacesTableEntry(uint32_t ifindex)
{
	struct interfaces_table_entry *e;
	bool r = false;

	if(HasInterfacesTableEntry(ifindex))
	{
		return true;
	}
	else
	{
		printk(KERN_ERR "SUPERMAN: interfaces_table - \t\tCreating a new entry...\n");
		e = kmalloc(sizeof(struct interfaces_table_entry), GFP_ATOMIC);
		if (e == NULL) {
			printk(KERN_ERR "interfaces_table: \t\t\t\"Out Of Memory\" in AddInterfacesTableEntry\n");
			return false;
		}
		memset(e, 0, sizeof(struct interfaces_table_entry));
		e->ifindex = ifindex;

		write_lock_bh(&interfaces_table_lock);
		r = __interfaces_table_add(e);
		if(r)
			interfaces_table_len++;
		write_unlock_bh(&interfaces_table_lock);

		if(!r)
			kfree(e);

		return r;
	}
}

bool AddInterfacesTableEntryByName(char* ifname)
{
	struct net_device* dev;
	uint32_t ifindex;

	// Find the index
	dev = dev_get_by_name(&init_net, ifname);
	if(dev == NULL) return false;
	ifindex = dev->ifindex;
	dev_put(dev);

	return AddInterfacesTableEntry(ifindex);
}

int interfaces_table_info_proc_show(struct seq_file *m, void *v)
{
	struct net_device *dev;

	read_lock_bh(&interfaces_table_lock);
	read_lock(&dev_base_lock);

	seq_printf(m, "%-6s %-20s %-16s %-16s %-10s\n", "Index", "Name", "Address", "Broadcast", "Secured");

	for_each_netdev(&init_net, dev) {
		bool hasEntry = (__interfaces_table_find(dev->ifindex) != NULL);
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

	read_unlock_bh(&interfaces_table_lock);
	read_unlock(&dev_base_lock);

	return 0;
}

void FlushInterfacesTable(void)
{
	write_lock_bh(&interfaces_table_lock);
	__interfaces_table_flush();
	write_unlock_bh(&interfaces_table_lock);
}

bool InitInterfacesTable(void)
{
	interfaces_table_len = 0;
	return true;
}

void DeInitInterfacesTable(void)
{
	FlushInterfacesTable();
}

#endif
