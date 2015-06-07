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
#include "security_table.h"
//#include "expl.h"
//#include "netlink.h"
//#include "ipenc.h"
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

void GetQueueInfo(int* length, int* maxLength)
{
	read_lock_bh(&queue_lock);

    	*length = queue_total;
	*maxLength = queue_maxlen;

	read_unlock_bh(&queue_lock);
}

struct rt_info {
	__u8 tos;
	__u32 daddr;
	__u32 saddr;
};

struct queue_entry {
	struct list_head list;
	struct sk_buff *skb;
	int (*okfn) (struct sk_buff *);
	struct rt_info rt_info;
};

typedef int (*queue_cmpfn) (struct queue_entry *, unsigned long);


static inline int __queue_enqueue_entry(struct queue_entry *entry)
{
	if (queue_total >= queue_maxlen) {
		if (net_ratelimit())
			printk(KERN_WARNING "SUPERMAN queue: full at %d entries, dropping packet(s).\n", queue_total);
		return -ENOSPC;
	}
	list_add(&entry->list, &queue_list);
	queue_total++;
	return 0;
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static inline struct queue_entry* __queue_find_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct list_head *p;
	list_for_each_prev(p, &queue_list) {
		struct queue_entry *entry = (struct queue_entry *)p;

		if (!cmpfn || cmpfn(entry, data))
			return entry;
	}
	return NULL;
}

static inline struct queue_entry* __queue_find_dequeue_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct queue_entry *entry;
	entry = __queue_find_entry(cmpfn, data);
	if (entry == NULL)
		return NULL;
	list_del(&entry->list);
	queue_total--;
	return entry;
}

static inline void __queue_flush(void)
{
	struct queue_entry *entry;
	while ((entry = __queue_find_dequeue_entry(NULL, 0))) {
		kfree_skb(entry->skb);
		kfree(entry);
	}
}

static inline void __queue_reset(void)
{
	__queue_flush();
}

static struct queue_entry* queue_find_dequeue_entry(queue_cmpfn cmpfn, unsigned long data)
{
	struct queue_entry *entry;
	write_lock_bh(&queue_lock);
	entry = __queue_find_dequeue_entry(cmpfn, data);
	write_unlock_bh(&queue_lock);
	return entry;
}

void FlushQueue(void)
{
	write_lock_bh(&queue_lock);
	__queue_flush();
	write_unlock_bh(&queue_lock);
}

int EnqueuePacket(struct sk_buff *skb, int (*okfn) (struct sk_buff *))
{
	int status = -EINVAL;
	struct queue_entry *entry;
	struct iphdr *iph = ((struct iphdr *)skb_network_header(skb));
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		printk(KERN_ERR "SUPERMAN queue: OOM in EnqueuePacket()\n");
		return -ENOMEM;
	}

	/* printk("enquing packet queue_len=%d\n", queue_total); */
	entry->okfn = okfn;
	entry->skb = skb;
	entry->rt_info.tos = iph->tos;
	entry->rt_info.daddr = iph->daddr;
	entry->rt_info.saddr = iph->saddr;

	write_lock_bh(&queue_lock);

	status = __queue_enqueue_entry(entry);

	if (status < 0)
		goto err_out_unlock;

	write_unlock_bh(&queue_lock);
	return status;

err_out_unlock:
	write_unlock_bh(&queue_lock);
	kfree(entry);

	return status;
}

static inline int dest_cmp(struct queue_entry *e, unsigned long daddr)
{
	return (daddr == e->rt_info.daddr);
}

int FindQueuedPacket(__u32 daddr)
{
	struct queue_entry *entry;
	int res = 0;

	read_lock_bh(&queue_lock);
	entry = __queue_find_entry(dest_cmp, daddr);
	if (entry != NULL)
		res = 1;

	read_unlock_bh(&queue_lock);
	return res;
}

int SetVerdict(int verdict, __u32 daddr)
{
	struct queue_entry *entry;
	int pkts = 0;

	if (verdict == SUPERMAN_QUEUE_DROP) {

		while (1) {
			entry = queue_find_dequeue_entry(dest_cmp, daddr);

			if (entry == NULL)
				return pkts;

			/* Send an ICMP message informing the application that the
			 * destination was unreachable. */
			if (pkts == 0)
				icmp_send(entry->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

			kfree_skb(entry->skb);
			kfree(entry);
			pkts++;
		}

	} else if (verdict == SUPERMAN_QUEUE_SEND) {
		struct security_table_entry e;

		while (1) {
			entry = queue_find_dequeue_entry(dest_cmp, daddr);

			if (entry == NULL)
				return pkts;

			if (!GetSecurityTableEntry(daddr, &e)) {
				kfree_skb(entry->skb);
				goto next;
			}
			//if (e.flags & KAODV_RT_GW_ENCAP)
			{
				// DO SOME SUPERMAN!
				// We need to check whether we're E2E or P2P at this stage.
				// ReceiveP2PPacket(entry->skb);
				// or
				// ReceiveE2EPacket(entry->skb);
				// On failure, goto next;
			}

			ip_route_me_harder(entry->skb, RTN_LOCAL);
			pkts++;

			/* Inject packet */
			entry->okfn(entry->skb);
next:
			kfree(entry);
		}
	}
	return 0;
}



void InitQueue(void)
{
	queue_total = 0;	
}

void DeInitQueue(void)
{
	FlushQueue();
}

