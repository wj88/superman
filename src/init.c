#ifdef __KERNEL__

#include "superman.h"
#include "init.h"
#include "security.h"
#include "security_table.h"
#include "interfaces_table.h"
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
	if(InitProc())
	{	
		if(InitQueue())
		{
			if(InitSecurityTable())
			{
				if(InitInterfacesTable())
				{
					if(InitSecurity())
					{
						if(InitNetlink())
						{
							if(InitNetFilter())
							{
								printk(KERN_INFO "SUPERMAN: module loaded successfully.\n");
								return 0;
							}
							DeInitNetlink();
						}
						DeInitSecurity();
					}
					DeInitInterfacesTable();
				}
				DeInitSecurityTable();
			}
			DeInitQueue();
		}
		DeInitProc();
	}
	printk(KERN_INFO "SUPERMAN: module failed to load.\n");
	return -1;
}

void DeInit(void)
{
	DeInitNetFilter();
	DeInitNetlink();
	DeInitSecurity();
	DeInitInterfacesTable();
	DeInitSecurityTable();
	DeInitQueue();
	DeInitProc();
	printk(KERN_INFO "SUPERMAN: module is being unloaded.\n");
}

module_init(Init);
module_exit(DeInit);

MODULE_AUTHOR("Dr Jodie Wetherall <wj88@gre.ac.uk>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Implementation of SUPERMAN (Security Under Pre-Existing Routing for Mobile Ad-hoc Networks).");

#endif
