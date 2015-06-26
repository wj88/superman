#ifdef __KERNEL__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/icmp.h>

#include "queue.h"
#include "packet_info.h"
#include "security_table.h"
#include "superman.h"
#include "packet.h"

/*
 * This is basically a shameless rippoff of the AODV-UU implementation
 * which is a shameless rippoff of the linux kernel's ip_queue module.
 */

#define QUEUE_QMAX_DEFAULT 1024
#define NET_QUEUE_QMAX 2088
#define NET_QUEUE_QMAX_NAME "queue_maxlen"

static unsigned int queue_maxlen = QUEUE_QMAX_DEFAULT;
static rwlock_t queue_lock = __RW_LOCK_UNLOCKED(queue_lock);
static unsigned int queue_total;
static LIST_HEAD(queue_list);

typedef int (*queue_cmpfn) (struct superman_packet_info*, unsigned long);

static inline int __queue_enqueue_entry(struct superman_packet_info* spi)
{
	if (queue_total >= queue_maxlen) {
		if (net_ratelimit())
			printk(KERN_WARNING "SUPERMAN queue: full at %d entries, dropping packet(s).\n", queue_total);
		return -ENOSPC;
	}
	list_add(&spi->list, &queue_list);
	queue_total++;
	return 0;
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static inline struct superman_packet_info* __queue_find_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct list_head *p;
	list_for_each_prev(p, &queue_list) {
		struct superman_packet_info *spi = (struct superman_packet_info*)p;

		if (!cmpfn || cmpfn(spi, data))
			return spi;
	}
	return NULL;
}

static inline struct superman_packet_info* __queue_find_dequeue_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct superman_packet_info* spi;
	spi = __queue_find_entry(cmpfn, data);
	if (spi == NULL)
		return NULL;
	list_del(&spi->list);
	queue_total--;
	return spi;
}

static inline void __queue_flush(void)
{
	struct superman_packet_info* spi;
	while ((spi = __queue_find_dequeue_entry(NULL, 0))) {
		FreeSupermanPacketInfo(spi);
	}
}

static inline void __queue_reset(void)
{
	__queue_flush();
}

static struct superman_packet_info* queue_find_dequeue_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct superman_packet_info* spi;
	write_lock_bh(&queue_lock);
	spi = __queue_find_dequeue_entry(cmpfn, data);
	write_unlock_bh(&queue_lock);
	return spi;
}

void FlushQueue(void)
{
	write_lock_bh(&queue_lock);
	__queue_flush();
	write_unlock_bh(&queue_lock);
}

int EnqueuePacket(struct superman_packet_info* spi, unsigned int (*callback_after_queue)(struct superman_packet_info*, bool))
{
	int status = -EINVAL;
	spi->arg = callback_after_queue;

	/* printk("enquing packet queue_len=%d\n", queue_total); */
	write_lock_bh(&queue_lock);
	status = __queue_enqueue_entry(spi);
	if (status < 0)
		goto err_out_unlock;
	write_unlock_bh(&queue_lock);
	return status;

err_out_unlock:
	write_unlock_bh(&queue_lock);

	return status;
}

static inline int dest_cmp(struct superman_packet_info* spi, unsigned long daddr)
{
	return (daddr == spi->addr);
}

int FindQueuedPacket(__u32 daddr)
{
	struct superman_packet_info* spi;
	int res = 0;

	read_lock_bh(&queue_lock);
	spi = __queue_find_entry(dest_cmp, daddr);
	if (spi != NULL)
		res = 1;

	read_unlock_bh(&queue_lock);
	return res;
}

int SetVerdict(int verdict, __u32 daddr)
{
	struct superman_packet_info* spi;
	int pkts = 0;

	if (verdict == SUPERMAN_QUEUE_DROP)
	{
		while (1) {
			spi = queue_find_dequeue_entry(dest_cmp, daddr);

			if (spi == NULL)
				return pkts;

			/* Send an ICMP message informing the application that the
			 * destination was unreachable. */
			if (pkts == 0)
				icmp_send(spi->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

			FreeSupermanPacketInfo(spi);
			pkts++;
		}

	}
	else if (verdict == SUPERMAN_QUEUE_SEND)
	{
		struct security_table_entry* entry;
		unsigned int (*callback_after_queue)(struct superman_packet_info*, bool);

		while (1) {
			spi = queue_find_dequeue_entry(dest_cmp, daddr);

			if (spi == NULL)
				return pkts;

			callback_after_queue = (unsigned int (*)(struct superman_packet_info*, bool)) spi->arg;
			spi->arg = NULL;

			if (GetSecurityTableEntry(daddr, &entry))
				callback_after_queue(spi, true);
			else
				callback_after_queue(spi, false);

			pkts++;
		}
	}
	return 0;
}

int queue_info_proc_show(struct seq_file *m, void *v)
{
	uint32_t countAddrs = 0;
	uint32_t* addrs;
	struct list_head *a;
	int i;

	read_lock_bh(&queue_lock);

	addrs = kmalloc(sizeof(uint32_t) * queue_total, GFP_ATOMIC);

	list_for_each(a, &queue_list) {
		struct superman_packet_info *spi = (struct superman_packet_info*)a;
		bool found = false;
		
		for(i = 0; i < countAddrs; i++)
		{
			if(spi->addr == addrs[i])
			{
				found = true;
				break;
			}
		}

		if(!found)
			addrs[countAddrs++] = spi->addr;
	}


 	seq_printf(m, "%-20s %u\n%-20s %u\n\n", "Queue length:", queue_total, "Queue max. length:", queue_maxlen);

	seq_printf(m, "%-20s %s\n", "Addr", "# Packets");

	for(i = 0; i < countAddrs; i++)
	{
		uint32_t count = 0;
		char addr[16];
		sprintf(addr, "%u.%u.%u.%u", (0x0ff & addrs[i]), (0x0ff & (addrs[i] >> 8)), (0x0ff & (addrs[i] >> 16)), (0x0ff & (addrs[i] >> 24)));

		list_for_each(a, &queue_list) {
			struct superman_packet_info *spi = (struct superman_packet_info*)a;
			if(addrs[i] == spi->addr)
				count++;
		}

		seq_printf(m, "%-20s %u\n", addr, count);
	}

	kfree(addrs);

	read_unlock_bh(&queue_lock);

   
	return 0;
}

bool InitQueue(void)
{
	queue_total = 0;
	return true;	
}

void DeInitQueue(void)
{
	FlushQueue();
}

#endif
