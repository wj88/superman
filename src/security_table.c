#ifdef __KERNEL__

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
		kfree(e->sk);
		kfree(e->ske);
		kfree(e->skp);
		kfree(e);
	}
}

static inline bool __security_table_add(struct security_table_entry *e)
{
	if (security_table_len >= SECURITY_TABLE_MAX_LEN) {
		printk(KERN_WARNING "SUPERMAN: security_table - \tMax list len reached (%d items).\n", SECURITY_TABLE_MAX_LEN);
		return false;
	}

	if (list_empty(&security_table_head)) {
		list_add(&e->l, &security_table_head);
	}
	else
	{
		list_add_tail(&e->l, &security_table_head);
	}
	return true;
}

static inline struct security_table_entry *__security_table_find(uint32_t daddr)
{
	struct list_head *pos;

	list_for_each(pos, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;

		if (e->daddr == daddr)
			return e;
	}
	return NULL;
}

static inline bool __security_table_del(struct security_table_entry *e)
{
	if (e == NULL)
		return false;

	list_del(&e->l);

	security_table_len--;

	return true;
}

bool DeleteSecurityTableEntry(uint32_t daddr)
{
	struct security_table_entry *e;

	write_lock_bh(&security_table_lock);

	if ((e = __security_table_find(daddr)) && __security_table_del(e))
	{
		if(e->sk)
			kfree(e->sk);
		if(e->ske)
			kfree(e->ske);
		if(e->skp)
			kfree(e->skp);
		e->sk = NULL;
		e->ske = NULL;
		e->skp = NULL;
		kfree(e);
		write_unlock_bh(&security_table_lock);
		return true;
	}
	
	write_unlock_bh(&security_table_lock);
	return false;
}

bool HasSecurityTableEntry(uint32_t daddr)
{
	struct security_table_entry* entry;
	read_lock_bh(&security_table_lock);
	entry = __security_table_find(daddr);
	read_unlock_bh(&security_table_lock);
	return entry != NULL;
}

bool GetSecurityTableEntry(uint32_t daddr, struct security_table_entry** entry)
{
	if(!entry) return false;

	read_lock_bh(&security_table_lock);
	*entry = __security_table_find(daddr);
	read_unlock_bh(&security_table_lock);

	if (*entry) {
		return true;
	}

	return false;
}

bool UpdateSecurityTableEntry(struct security_table_entry *e, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp, int32_t ifindex)
{
	ClearSecurityTableEntry(e);
	e->daddr = daddr;
	e->flag = flag;
	if(timestamp != -1) e->timestamp = timestamp;
	if(timestamp != -1) e->ifindex = ifindex;

	if(
		((sk_len == 0) || (e->sk = kmalloc(sk_len, GFP_ATOMIC))) &&
		((ske_len == 0) || (e->ske = kmalloc(ske_len, GFP_ATOMIC))) &&
		((skp_len == 0) || (e->skp = kmalloc(skp_len, GFP_ATOMIC)))
	)
	{
		e->sk_len = sk_len;
		e->ske_len = ske_len;
		e->skp_len = skp_len;
		if(sk_len > 0) memcpy(e->sk, sk, sk_len);
		if(ske_len > 0) memcpy(e->ske, ske, ske_len);
		if(skp_len > 0) memcpy(e->skp, skp, skp_len);
		return true;
	}
	else
		return false;
}

void ClearSecurityTableEntry(struct security_table_entry *e)
{
	if(e)
	{
		if(e->sk) kfree(e->sk);
		if(e->ske) kfree(e->ske);
		if(e->skp) kfree(e->skp);
		e->sk = NULL;
		e->ske = NULL;
		e->skp = NULL;
	}
}

bool UpdateOrAddSecurityTableEntry(uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp, int32_t ifindex)
{
	struct security_table_entry *e;
	bool r = false;

	if(GetSecurityTableEntry(daddr, &e))
	{
		printk(KERN_ERR "SUPERMAN: security_table - \t\tUpdating an existing entry...\n");
		if(!UpdateSecurityTableEntry(e, daddr, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex))
		{
			DeleteSecurityTableEntry(daddr);
			printk(KERN_ERR "SUPERMAN: security_table - \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
			return false;
		}
		else
			return true;
	}
	else
	{
		printk(KERN_ERR "SUPERMAN: security_table - \t\tCreating a new entry...\n");
		e = kmalloc(sizeof(struct security_table_entry), GFP_ATOMIC);
		if (e == NULL) {
			printk(KERN_ERR "security_table: \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
			return false;
		}
		memset(e, 0, sizeof(struct security_table_entry));

		if(!UpdateSecurityTableEntry(e, daddr, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex))
		{
			DeleteSecurityTableEntry(daddr);
			printk(KERN_ERR "SUPERMAN: security_table - \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
			return false;
		}

		write_lock_bh(&security_table_lock);
		r = __security_table_add(e);
		if(r)
			security_table_len++;
		write_unlock_bh(&security_table_lock);

		if(!r)
		{
			ClearSecurityTableEntry(e);
			kfree(e);
		}

		return r;
	}
}

int security_table_info_proc_show(struct seq_file *m, void *v)
{
	struct list_head *pos;

	read_lock_bh(&security_table_lock);

	seq_printf(m, "# Total entries: %u\n", security_table_len);
	seq_printf(m, "%-15s %-6s %-16s %-16s %-16s\n", "Addr", "Flag", "SK Len (bits)", "SKE Len (bits)", "SKP Len (bits)");

	list_for_each(pos, &security_table_head) {
		char addr[16];
		struct security_table_entry *e = (struct security_table_entry *)pos;

		sprintf(addr, "%u.%u.%u.%u", (0x0ff & e->daddr), (0x0ff & (e->daddr >> 8)), (0x0ff & (e->daddr >> 16)), (0x0ff & (e->daddr >> 24)));
		seq_printf(m, "%-15s %-6d %-16d %-16d %-16d\n", addr, e->flag, (e->sk_len * 8), (e->ske_len * 8), (e->skp_len * 8));
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

bool InitSecurityTable(void)
{
	security_table_len = 0;
	return true;
}

void DeInitSecurityTable(void)
{
	FlushSecurityTable();
}

#endif
