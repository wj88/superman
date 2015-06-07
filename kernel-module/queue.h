#ifndef _SUPERMAN_QUEUE_H
#define _SUPERMAN_QUEUE_H

#define SUPERMAN_QUEUE_DROP 1
#define SUPERMAN_QUEUE_SEND 2

int FindQueuedPacket(__u32 daddr);
int EnqueuePacket(struct sk_buff *skb, int (*okfn) (struct sk_buff *));
int SetVerdict(int verdict, __u32 daddr);
void FlushQueue(void);

void InitQueue(void);
void DeInitQueue(void);
void GetQueueInfo(int* length, int* maxLength);

#endif

