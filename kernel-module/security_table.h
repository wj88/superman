#ifndef _SUPERMAN_SECURITY_TABLE_H
#define _SUPERMAN_SECURITY_TABLE_H

#ifdef __KERNEL__

#include <linux/list.h>

struct security_table_entry {
	struct	list_head l;
	__u32	daddr;
	__u8	auth_key[16];
	__u8	enc_key[16];
	int	ifindex;
};

void InitSecurityTable(void);
void DeInitSecurityTable(void);
void FlushSecurityTable(void);

int GetSecurityTableEntry(__u32 daddr, struct security_table_entry *e_in);
int AddSecurityTableEntry(__u32 daddr, __u8 auth_key[16], __u8 enc_key[16], int ifindex);
int DeleteSecurityTableEntry(__u32 daddr);

int security_table_info_proc_show(struct seq_file *m, void *v);

#endif

#endif

