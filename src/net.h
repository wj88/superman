#ifndef _SUPERMAN_NET_H
#define _SUPERMAN_NET_H

#ifdef __KERNEL__


struct superman_net {
    // Add the per net data structures here
    void* queue;
    void* interfaces_table;
    void* security_table;
};


bool InitNet(void);
void DeInitNet(void);

struct net* GetNet(void);
struct superman_net* GetSupermanNetFromNet(const struct net *net);
struct superman_net* GetSupermanNet(void);
void UnloadSupermanNet(void);

#endif

#endif