#ifndef _SUPERMAN_SECURITY_TABLE_H
#define _SUPERMAN_SECURITY_TABLE_H

#ifdef __KERNEL__

#include <linux/list.h>

struct security_table_entry {
	struct		list_head l;
	uint32_t	daddr;
	uint8_t		flag;
	uint32_t	sk_len;
	unsigned char*	sk;
	uint32_t	ske_len;
	unsigned char*	ske;
	uint32_t	skp_len;
	unsigned char*	skp;
};

bool UpdateBroadcastKey(uint32_t key_len, unsigned char* key);
bool HasBroadcastKey(void);
bool MallocAndCopyBroadcastKey(uint32_t* key_len, unsigned char** key);

void InitSecurityTable(void);
void DeInitSecurityTable(void);
void FlushSecurityTable(void);

bool GetSecurityTableEntry(uint32_t daddr, struct security_table_entry** entry);
bool UpdateOrAddSecurityTableEntry(uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp);
bool DeleteSecurityTableEntry(uint32_t daddr);

int security_table_info_proc_show(struct seq_file *m, void *v);

#endif

#endif

