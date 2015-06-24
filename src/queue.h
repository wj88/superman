#ifndef _SUPERMAN_QUEUE_H
#define _SUPERMAN_QUEUE_H

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include "packet_info.h"

#define SUPERMAN_QUEUE_DROP 1
#define SUPERMAN_QUEUE_SEND 2

int FindQueuedPacket(__u32 daddr);
int EnqueuePacket(struct superman_packet_info* spi, unsigned int (*callback_after_queue)(struct superman_packet_info*, bool));
int SetVerdict(int verdict, __u32 daddr);
void FlushQueue(void);

void InitQueue(void);
void DeInitQueue(void);
void GetQueueInfo(int* length, int* maxLength);

#endif

#endif
