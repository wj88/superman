#ifndef _SUPERMAN_QUEUE_H
#define _SUPERMAN_QUEUE_H

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include "packet_info.h"

#define SUPERMAN_QUEUE_DROP 1
#define SUPERMAN_QUEUE_SEND 2

int FindQueuedPacket(__u32 daddr);
int EnqueuePacket(struct superman_packet_info* spi, __be32 addr, unsigned int (*callback_after_queue)(struct superman_packet_info*, bool));
int SetVerdict(int verdict, __u32 daddr);
void FlushQueue(void);

bool InitQueue(void);
void DeInitQueue(void);

int queue_info_proc_show(struct seq_file *m, void *v);

#endif

#endif
