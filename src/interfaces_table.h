#ifndef _SUPERMAN_INTERFACES_TABLE_H
#define _SUPERMAN_INTERFACES_TABLE_H

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/spinlock.h>
#include "net.h"

struct interfaces_table_entry {
	struct list_head	l;
	struct net 			*net;
	int32_t				ifindex;
};

struct interfaces_table {
	rwlock_t interfaces_table_lock;
    struct list_head interfaces_table_head;
    unsigned int interfaces_table_total;
};

struct interfaces_table* GetInterfacesTable(void);


#define INTERFACE_ITERATOR_START(DEV_VAR)																			\
	{																												\
		struct net* net = GetNet();																					\
		struct interfaces_table* it = GetInterfacesTable();															\
		int i = 0;																									\
		int32_t* interfaces = NULL;																					\
		read_lock_bh(&it->interfaces_table_lock);																	\
		{																											\
			if(it->interfaces_table_total > 0)																		\
			{																										\
				interfaces = kmalloc(it->interfaces_table_total * sizeof(int32_t), GFP_ATOMIC);						\
				if(interfaces != NULL)																				\
				{																									\
					struct list_head *pos;																			\
					list_for_each(pos, &it->interfaces_table_head) {													\
						interfaces[i++] = ((struct interfaces_table_entry *)pos)->ifindex;							\
					}																								\
				}																									\
			}																										\
		}																											\
		read_unlock_bh(&it->interfaces_table_lock);																	\
		for(i = 0; i < it->interfaces_table_total; i++)																\
		{																											\
			uint32_t ifindex = interfaces[i];																		\
			DEV_VAR = dev_get_by_index(net, ifindex);																\
			if(DEV_VAR == NULL)																						\
			{																										\
				printk(KERN_INFO "SUPERMAN: Interfaces Iterator - \t\tNo device for interface %i.\n", ifindex);		\
				continue;																							\
			}																										\
			else																									\
			{

#define INTERFACE_ITERATOR_END																						\
			}																										\
			dev_put(dev);																							\
		}																											\
		kfree(interfaces);																							\
		put_net(net);																								\
	}


bool InitInterfacesTable(struct superman_net* snet);
void DeInitInterfacesTable(struct superman_net* snet);

uint32_t GetInterfaceFromName(char* ifname);
bool HasInterfacesTableEntry(uint32_t ifindex);
bool AddInterfacesTableEntry(uint32_t ifindex);
bool RemoveInterfacesTableEntry(uint32_t ifindex);

int interfaces_table_info_proc_show(struct seq_file *m, void *v);

#endif

#endif
