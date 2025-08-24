#ifndef _SUPERMAN_SECURITY_TABLE_H
#define _SUPERMAN_SECURITY_TABLE_H

enum {
	SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE = 1,
#define SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE

	SUPERMAN_SECURITYTABLE_FLAG_SEC_REQUESTED = 2,
#define SUPERMAN_SECURITYTABLE_FLAG_SEC_REQUESTED SUPERMAN_SECURITYTABLE_FLAG_SEC_REQUESTED

	SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED = 3,
#define SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED

	SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED = 4,
#define SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED
};

#ifdef __KERNEL__

#include <linux/list.h>
#include "net.h"

struct security_table_entry {
	struct list_head 	l;
	uint32_t 			daddr;
	uint8_t 			flag;
	uint32_t 			sk_len;
	unsigned char* 		sk;
	uint32_t 			ske_len;
	unsigned char* 		ske;
	uint32_t 			skp_len;
	unsigned char* 		skp;
	int16_t 			timestamp;
	int32_t 			ifindex;
};

uint16_t GetNextTimestampFromSecurityTableEntry(uint32_t ifindex, uint32_t addr);

bool InitSecurityTable(struct superman_net* snet);
void DeInitSecurityTable(struct superman_net* snet);

bool GetSecurityTableEntry(uint32_t ifindex, uint32_t daddr, struct security_table_entry** entry);
bool AddSecurityTableEntry(uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp);
bool UpdateOrAddSecurityTableEntry(uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp);
bool RemoveSecurityTableEntry(uint32_t ifindex, uint32_t daddr);

bool UpdateSecurityTableEntry(struct security_table_entry *e, uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp);
void ClearSecurityTableEntry(struct security_table_entry *e);
bool UpdateSecurityTableEntryFlag(uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t timestamp);

bool UpdateBroadcastKey(uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite);
bool GetBroadcastKey(uint32_t ifindex, uint32_t* sk_len, unsigned char** sk);
bool HasBroadcastKey(uint32_t ifindex);

int security_table_info_proc_show(struct seq_file *m, void *v);

#endif

#endif
