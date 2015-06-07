#ifndef __SUPERMAN_NETLINK_H
#define __SUPERMAN_NETLINK_H

#include "superman.h"

#ifdef __KERNEL__

void InvokeSupermanDiscoveryRequest();

#else

bool InvokeCertificateRequest(void** data, int* data_size);

#endif

#endif

