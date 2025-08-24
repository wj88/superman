#ifdef __KERNEL__

#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include "net.h"
#include "queue.h"
#include "interfaces_table.h"

// Define our prototypes to prevent kernel build warnings
bool init_superman_net(struct superman_net *snet);
bool deinit_superman_net(struct superman_net *snet);

static unsigned int superman_net_id __read_mostly;
static struct mutex superman_net_lock;

bool init_superman_net(struct superman_net *snet)
{
    if (!snet)
        return false;

    if (!InitQueue(snet)) {
        printk(KERN_WARNING "SUPERMAN net: Failed to initialize queue.\n");
        return false;
    }

    if (!InitInterfacesTable(snet)) {
        printk(KERN_WARNING "SUPERMAN net: Failed to initialize interfaces table.\n");
        return false;
    }

    if (!InitSecurityTable(snet)) {
        printk(KERN_WARNING "SUPERMAN net: Failed to initialize security table.\n");
        return false;
    }

    return true;
}

bool deinit_superman_net(struct superman_net *snet)
{
    if (!snet)
        return false;

    DeInitQueue(snet);
    DeInitInterfacesTable(snet);
    DeInitSecurityTable(snet);

    return true;
}

static int __net_init superman_net_init(struct net* net)
{
    int result = 0;
    mutex_lock(&superman_net_lock);
    struct superman_net *snet;
    snet = net_generic(net, superman_net_id);
    if (snet)
    {
        if (!init_superman_net(snet))
        {
            printk(KERN_WARNING "SUPERMAN net: Failed to initialize superman_net.\n");
            result = -ENOMEM;
        }
    }
    else
    {
        printk(KERN_WARNING "SUPERMAN net: Failed to obtain superman_net.\n");
        result = -ENOMEM;
    }
    mutex_unlock(&superman_net_lock);
    return result;
}

static void __net_exit superman_net_exit(struct net* net)
{    
    mutex_lock(&superman_net_lock);

    struct superman_net *snet;
    snet = net_generic(net, superman_net_id);
    if (snet)
        deinit_superman_net(snet);

    mutex_unlock(&superman_net_lock);
}

static struct pernet_operations superman_net_ops = {
    .init = superman_net_init,
    .exit = superman_net_exit,
    .id   = &superman_net_id,
    .size = sizeof(struct superman_net),
};

bool InitNet(void)
{
    mutex_init(&superman_net_lock);
    int ret = register_pernet_subsys(&superman_net_ops);
    if (ret != 0) {
        printk(KERN_WARNING "SUPERMAN net: Failed to register pernet subsystem (err=%d)\n", ret);
        return false;
    }    
    return true;
}

void DeInitNet(void)
{
    unregister_pernet_subsys(&superman_net_ops);
    mutex_destroy(&superman_net_lock);
}

struct net* GetNet(void)
{
    return get_net(current->nsproxy->net_ns);
}

struct superman_net* GetSupermanNetFromNet(const struct net *net)
{
    return net_generic(net, superman_net_id);
}

struct superman_net* GetSupermanNet()
{
    struct net *net = GetNet();
    struct superman_net* superman_net = GetSupermanNetFromNet(net);
    put_net(net);
    return superman_net;
}

void UnloadSupermanNet()
{
    mutex_lock(&superman_net_lock);
    
    struct superman_net* superman_net = GetSupermanNet();    
    deinit_superman_net(superman_net);
    init_superman_net(superman_net);

    mutex_unlock(&superman_net_lock);
}

#endif