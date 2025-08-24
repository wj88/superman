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

// Define our prototypes to prevent kernel build warnings
struct queue* GetQueue(void);

/*
 * This is basically a shameless rippoff of the AODV-UU implementation
 * which is a shameless rippoff of the linux kernel's ip_queue module.
 */

#define QUEUE_QMAX_DEFAULT 1024
#define NET_QUEUE_QMAX 2088
#define NET_QUEUE_QMAX_NAME "queue_maxlen"

struct queue {
	rwlock_t queue_lock;
    struct list_head queue_list;
    unsigned int queue_total;
};

static unsigned int queue_maxlen = QUEUE_QMAX_DEFAULT;
// static rwlock_t queue_lock = __RW_LOCK_UNLOCKED(queue_lock);
// static unsigned int queue_total;
// static LIST_HEAD(queue_list);

typedef int (*queue_cmpfn) (struct superman_packet_info*, unsigned long);

struct queue* GetQueue()
{
	struct superman_net* snet = GetSupermanNet();
	return (struct queue*)snet->queue;
}

static inline int __queue_enqueue_entry(struct queue* queue, struct superman_packet_info* spi)
{
	if (queue->queue_total < queue_maxlen)
	{
		//write_lock_bh(&q->queue_lock);
		list_add(&spi->list, &queue->queue_list);
		queue->queue_total++;
		//write_unlock_bh(&q->queue_lock);	
		return 0;
	}
	else
	{
		printk(KERN_WARNING "SUPERMAN queue: full at %d entries, dropping packet(s).\n", queue->queue_total);
		return -ENOSPC;
	}
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static inline struct superman_packet_info* __queue_find_entry(struct queue* queue, uint32_t ifindex, uint32_t addr)
{
	struct list_head *p;
	list_for_each_prev(p, &queue->queue_list) {
		struct superman_packet_info *spi = (struct superman_packet_info*)p;

		if(
			(ifindex == 0 && addr == 0) ||
			(spi->dev->ifindex == ifindex && addr == spi->queue_addr))
			return spi;
	}
	return NULL;
}

static inline struct superman_packet_info* __queue_find_dequeue_entry(struct queue* queue, uint32_t ifindex, uint32_t addr)
{
	struct superman_packet_info* spi;
	spi = __queue_find_entry(queue, ifindex, addr);
	if (spi == NULL)
		return NULL;
	list_del(&spi->list);
	queue->queue_total--;
	return spi;
}

static inline void __queue_flush(struct queue* queue)
{
	struct superman_packet_info* spi;
	while ((spi = __queue_find_dequeue_entry(queue, 0, 0))) {
		FreeSupermanPacketInfo(spi);
	}
}

static inline void __queue_reset(struct queue* queue)
{
	__queue_flush(queue);
}

static struct superman_packet_info* queue_find_dequeue_entry(struct queue* queue, uint32_t ifindex, uint32_t addr)
{
	struct superman_packet_info* spi;
	write_lock_bh(&queue->queue_lock);
	spi = __queue_find_dequeue_entry(queue, ifindex, addr);
	write_unlock_bh(&queue->queue_lock);
	return spi;
}

int EnqueuePacket(struct superman_packet_info* spi, uint32_t addr, unsigned int (*callback_after_queue)(struct superman_packet_info*, bool))
{
	struct queue* q = GetQueue();
	if (!q)
		return -ENOMEM;

	int status = -EINVAL;
	spi->queue_addr = addr;
	ktime_get_real_ts64(&spi->queue_entry_time);
	spi->arg = callback_after_queue;

	/* printk("enquing packet queue_len=%d\n", queue_total); */
	write_lock_bh(&q->queue_lock);
	status = __queue_enqueue_entry(q, spi);
	write_unlock_bh(&q->queue_lock);
	return status;
}

int FindQueuedPacket(uint32_t ifindex, uint32_t addr)
{
	struct queue* q = GetQueue();
	if (!q)
		return -ENOMEM;

	struct superman_packet_info* spi;
	int res = 0;

	read_lock_bh(&q->queue_lock);
	spi = __queue_find_entry(q, ifindex, addr);
	if (spi != NULL)
		res = 1;
	read_unlock_bh(&q->queue_lock);
	return res;
}

int SetVerdict(int verdict, uint32_t ifindex, uint32_t addr)
{
	struct queue* q = GetQueue();
	if (!q)
		return -ENOMEM;

	struct superman_packet_info* spi;
	int pkts = 0;

	if (verdict == SUPERMAN_QUEUE_DROP)
	{
		while (1) {
			spi = queue_find_dequeue_entry(q, ifindex, addr);

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
		bool r = false;
		if (GetSecurityTableEntry(ifindex, addr, &entry) && entry->flag == SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
			r = true;

		while (1) {
			spi = queue_find_dequeue_entry(q, ifindex, addr);

			if (spi == NULL)
				return pkts;

			// Grab the callback function from the spi->arg and reset the arg.
			callback_after_queue = (unsigned int (*)(struct superman_packet_info*, bool)) spi->arg;
			spi->arg = NULL;

			//printk(KERN_INFO "SUPERMAN: queue: \tDequeued superman_packet_info (id: %u)...\n", spi->id);

			// Refresh our spi to get the security details which we should now have.
			RefreshSupermanPacketInfo(spi);

			// Call the callback to reinject the packet into the processing pipeline where it left off.
			callback_after_queue(spi, r);

			pkts++;
		}
	}
	return 0;
}

int queue_info_proc_show(struct seq_file *m, void *v)
{
	struct net *net = GetNet();
	if(net)
	{
		struct queue* q = GetQueue();
		if (!q)
			return -ENOMEM;

		uint32_t countAddrs = 0;
		uint32_t* addrs;
		struct list_head *a;
		int i;

		read_lock_bh(&q->queue_lock);

		addrs = kmalloc(sizeof(uint32_t) * q->queue_total, GFP_ATOMIC);

		list_for_each(a, &q->queue_list) {
			struct superman_packet_info *spi = (struct superman_packet_info*)a;

			bool found = false;

			for(i = 0; i < countAddrs; i++)
			{
				if(spi->queue_addr == addrs[i])
				{
					found = true;
					break;
				}
			}

			if(!found)
				addrs[countAddrs++] = spi->queue_addr;
		}


		seq_printf(m, "%-20s %u\n%-20s %u\n\n", "Queue length:", q->queue_total, "Queue max. length:", queue_maxlen);

		seq_printf(m, "%-20s %s\n", "Addr", "# Packets");

		for(i = 0; i < countAddrs; i++)
		{
			uint32_t count = 0;
			char addr[16];
			sprintf(addr, "%u.%u.%u.%u", (0x0ff & addrs[i]), (0x0ff & (addrs[i] >> 8)), (0x0ff & (addrs[i] >> 16)), (0x0ff & (addrs[i] >> 24)));

			list_for_each(a, &q->queue_list) {
				struct superman_packet_info *spi = (struct superman_packet_info*)a;
				if(addrs[i] == spi->queue_addr)
					count++;
			}

			seq_printf(m, "%-20s %u\n", addr, count);
		}

		kfree(addrs);

		read_unlock_bh(&q->queue_lock);

		put_net(net);
	}

	return 0;
}

/*
bool EnqueueSKRequest(uint32_t originaddr, uint32_t targetaddr)
{
	send_sk_request_item* item = (send_sk_request_item*)kmalloc(sizeof(send_sk_request_item), GFP_KERNEL);
	if(!item)
	{
		printk(KERN_ERR "SUPERMAN: Queue - EnqueueSKRequest kmalloc failed.\n");
		return false;
	}

	INIT_WORK((struct work_struct *)item, send_sk_request_callback);
	item->originaddr = originaddr;
	item->targetaddr = targetaddr;
	//queue_work(workqueue, (struct work_struct *)item);
	schedule_work((struct work_struct *)item);
	return true;
}
*/

bool InitQueue(struct superman_net* snet)
{
	snet->queue = kmalloc(sizeof(struct queue), GFP_KERNEL);
	if(!snet->queue)
	{
		printk(KERN_WARNING "SUPERMAN queue: unable to create the queue.\n");
		return false;
	}
	struct queue* q = (struct queue*)snet->queue;

	INIT_LIST_HEAD(&q->queue_list);
	q->queue_lock = __RW_LOCK_UNLOCKED(q->queue_lock);
	q->queue_total = 0;
	return true;
}

void DeInitQueue(struct superman_net* snet)
{
	struct queue* q = (struct queue*)snet->queue;
	if (q)
	{
		write_lock_bh(&q->queue_lock);
		__queue_flush(q);
		write_unlock_bh(&q->queue_lock);

		kfree(q);
		snet->queue = NULL;
	}
}

#endif
