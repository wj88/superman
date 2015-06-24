#ifdef __KERNEL__

#include "superman.h"
#include "security.h"
#include "security_table.h"
#include "queue.h"
#include "proc.h"
#include "netlink.h"
#include "netfilter.h"

/*
Init and DeInit are our modules entry points.
*/

int Init(void)
{
	printk(KERN_INFO "SUPERMAN: module is being loaded.\n");
	InitProc();
	InitSecurity();
	InitSecurityTable();
	InitQueue();
	InitNetFilter();
	InitNetlink();
	return 0;
}

void DeInit(void)
{
	DeInitNetlink();
	DeInitNetFilter();
	DeInitQueue();
	DeInitSecurityTable();
	DeInitSecurity();
	DeInitProc();
	printk(KERN_INFO "SUPERMAN: module is being unloaded.\n");
}

module_init(Init);
module_exit(DeInit);

MODULE_AUTHOR("Dr Jodie Wetherall <wj88@gre.ac.uk>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Implementation of SUPERMAN (Security Under Pre-Existing Routing for Mobile Ad-hoc Networks).");

#endif
