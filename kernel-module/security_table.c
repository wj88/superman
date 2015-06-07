#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>

#include "security_table.h"

#define SECURITY_TABLE_MAX_LEN 1024

static unsigned int security_table_len;
static rwlock_t security_table_lock = __RW_LOCK_UNLOCKED(security_table_lock);
static LIST_HEAD(security_table_head);

#define list_is_first(e) (&e->l == security_table_head.next)

static inline void __security_table_flush(void)
{
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;
		list_del(&e->l);
		security_table_len--;
		kfree(e);
	}
}

static inline int __security_table_add(struct security_table_entry *e)
{
	if (security_table_len >= SECURITY_TABLE_MAX_LEN) {
		printk(KERN_WARNING "security_table: Max list len reached\n");
		return -ENOSPC;
	}

	if (list_empty(&security_table_head)) {
		list_add(&e->l, &security_table_head);
	}
	else
	{
		list_add_tail(&e->l, &security_table_head);
	}
	return 1;
}

static inline struct security_table_entry *__security_table_find(__u32 daddr)
{
	struct list_head *pos;

	list_for_each(pos, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;

		if (e->daddr == daddr)
			return e;
	}
	return NULL;
}

static inline int __security_table_del(struct security_table_entry *e)
{
	if (e == NULL)
		return 0;

	list_del(&e->l);

	security_table_len--;

	return 1;
}

int DeleteSecurityTableEntry(__u32 daddr)
{
	int res;
	struct security_table_entry *e;

	write_lock_bh(&security_table_lock);

	e = __security_table_find(daddr);

	if (e == NULL) {
		res = 0;
		goto unlock;
	}
	
	res = __security_table_del(e);

	if (res) {
		kfree(e);
	}
unlock:
	write_unlock_bh(&security_table_lock);

	return res;
}

int GetSecurityTableEntry(__u32 daddr, struct security_table_entry *e_in)
{
	struct security_table_entry *e;
	int res = 0;

	read_lock_bh(&security_table_lock);
	e = __security_table_find(daddr);

	if (e) {
		res = 1;
		if (e_in)
			memcpy(e_in, e, sizeof(struct security_table_entry));
	}

	read_unlock_bh(&security_table_lock);
	return res;
}

int AddSecurityTableEntry(__u32 daddr, __u8 auth_key[16], __u8 enc_key[16], int ifindex)
{
	struct security_table_entry *e;
	int status = 0;
	int i;

	if (GetSecurityTableEntry(daddr, NULL))
		return 0;

	e = kmalloc(sizeof(struct security_table_entry), GFP_ATOMIC);

	if (e == NULL) {
		printk(KERN_ERR "security_table: OOM in AddSecurityTableEntry\n");
		return -ENOMEM;
	}

	e->daddr = daddr;

	
	for(i = 0; i < 16; i++)
	{
		e->auth_key[i] = auth_key[i];
		e->enc_key[i] = enc_key[i];
		e->ifindex = ifindex;
	}

	write_lock_bh(&security_table_lock);

	status = __security_table_add(e);

	if (status)
		security_table_len++;

	write_unlock_bh(&security_table_lock);

	if (status < 0)
		kfree(e);

	return status;
}

int security_table_info_proc_show(struct seq_file *m, void *v)
{
	struct list_head *pos;

	read_lock_bh(&security_table_lock);

	seq_printf(m, "# Total entries: %u\n", security_table_len);
	seq_printf(m, "\t%-15s %-5s\n", "Addr", "Iface");

	
	list_for_each(pos, &security_table_head) {
		char addr[16];
		struct security_table_entry *e = (struct security_table_entry *)pos;
		struct net_device *dev = dev_get_by_index(&init_net, e->ifindex);

		if (!dev)
			continue;

		sprintf(addr, "%d.%d.%d.%d ",
			   0x0ff & e->daddr,
			   0x0ff & (e->daddr >> 8),
			   0x0ff & (e->daddr >> 16),
			   0x0ff & (e->daddr >> 24));

		seq_printf(m, "\t%-15s %-5s\n",
			      addr, dev->name);

		dev_put(dev);
	}

	read_unlock_bh(&security_table_lock);

	return 0;
}

void FlushSecurityTable(void)
{
	write_lock_bh(&security_table_lock);

	__security_table_flush();

	write_unlock_bh(&security_table_lock);
}

void InitSecurityTable(void)
{
	security_table_len = 0;
}

void DeInitSecurityTable(void)
{
	FlushSecurityTable();
}

