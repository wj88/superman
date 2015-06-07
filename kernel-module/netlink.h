#ifndef __SUPERMAN_CMD_NETLINK_H
#define __SUPERMAN_CMD_NETLINK_H

#include "superman.h"

#ifdef __KERNEL__

#include <net/netlink.h>    // Common Netlink API
#include <net/genetlink.h>  // Special Generic Netlink API

#else

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#endif


#define SUPERMAN_GENL_VER		SUPERMAN_VERSION_MAJOR
#define SUPERMAN_GENL_FAMILY_NAME	"SUPERMAN"
#define SUPERMAN_GENL_GROUP_NAME	"SUPERMAN_MC"	// MC = Multicast

enum superman_genl_cmds
{
	SUPERMAN_CMD_UNSPEC = 0,

	SUPERMAN_CMD_SEND_DISCOVERY_REQUEST,
#define SUPERMAN_CMD_SEND_DISCOVERY_REQUEST SUPERMAN_CMD_SEND_DISCOVERY_REQUEST

	SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING,
#define SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING

	SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING,
#define SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING

	SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING,
#define SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING

	SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING,
#define SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING

	SUPERMAN_CMD_PROCESSED_INCOMING_PREROUTING,
#define SUPERMAN_CMD_PROCESSED_INCOMING_PREROUTING SUPERMAN_CMD_PROCESSED_INCOMING_PREROUTING

	SUPERMAN_CMD_PROCESSED_INCOMING_POSTROUTING,
#define SUPERMAN_CMD_PROCESSED_INCOMING_POSTROUTING SUPERMAN_CMD_PROCESSED_INCOMING_POSTROUTING

	SUPERMAN_CMD_PROCESSED_OUTGOING_PREROUTING,
#define SUPERMAN_CMD_PROCESSED_OUTGOING_PREROUTING SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING

	SUPERMAN_CMD_PROCESSED_OUTGOING_POSTROUTING,
#define SUPERMAN_CMD_PROCESSED_OUTGOING_POSTROUTING SUPERMAN_CMD_PROCESSED_OUTGOING_POSTROUTING

	__SUPERMAN_CMD_MAX,
#define SUPERMAN_CMD_MAX (__SUPERMAN_CMD_MAX - 1)
};

enum superman_genl_attrs
{
	__SUPERMAN_ATTR_FIRST = 0,
	SUPERMAN_ATTR_IFINDEX,
        SUPERMAN_ATTR_SRC_ADDR,
	SUPERMAN_ATTR_DST_ADDR,
	SUPERMAN_ATTR_PACKET_TYPE,
	SUPERMAN_ATTR_TIMESTAMP,
        SUPERMAN_ATTR_PAYLOAD,
        __SUPERMAN_ATTR_MAX,
#define SUPERMAN_ATTR_MAX (__SUPERMAN_ATTR_MAX - 1)
};

// A SUPERMAN policy.
static struct nla_policy superman_genl_pol[SUPERMAN_ATTR_MAX + 1] = {
        [SUPERMAN_ATTR_IFINDEX]	=		{ .type = NLA_U32 },
        [SUPERMAN_ATTR_SRC_ADDR]	=	{ .type = NLA_U32 },
        [SUPERMAN_ATTR_DST_ADDR]	=	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_PROTOCOL]	=	{ .type = NLA_U16 },
//	[SUPERMAN_ATTR_PACKET_TYPE]	=	{ .type = NLA_U8 },
//	[SUPERMAN_ATTR_TIMESTAMP]	=	{ .type = NLA_U16 },
        [SUPERMAN_ATTR_PAYLOAD]		=	{ .type = NLA_UNSPEC },
};


#ifdef __KERNEL__

// Family definition
static struct genl_family superman_genl_family = {
	.id		= GENL_ID_GENERATE, 		// 0 - Generate an ID
	.hdrsize	= 0,				// No custom header
	.name		= SUPERMAN_GENL_FAMILY_NAME,	// Our family name
	.version	= SUPERMAN_GENL_VER,		// Our version number
	.maxattr	= SUPERMAN_ATTR_MAX,		// Maximum number of attributes we support
};

// Multicast group definition
struct genl_multicast_group superman_mc_group = {
	.name = SUPERMAN_GROUP_NAME
};


int superman_send_discovery_request(struct sk_buff *skb_msg, struct genl_info *info);
int superman_processed_incoming_prerouting(struct sk_buff *skb_msg, struct genl_info *info)
int superman_processed_incoming_postrouting(struct sk_buff *skb_msg, struct genl_info *info)
int superman_processed_outgoing_prerouting(struct sk_buff *skb_msg, struct genl_info *info)
int superman_processed_outgoing_postrouting(struct sk_buff *skb_msg, struct genl_info *info)
int superman_dummy_doit(struct sk_buff *skb_msg, struct genl_info *info) { return 0; }

static struct genl_ops superman_ops[SUPERMAN_CMD_MAX] = {
	{
		.cmd	= SUPERMAN_CMD_SEND_DISCOVERY_REQUEST,		// The command
		.flags	= 0,						// No flags
		.policy	= 0,						// No attributes, therefore, no policy
		.doit	= superman_send_discovery_request,		// Our handlers for discovery request messages
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_dummy_doit,				// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_dummy_doit,				// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_dummy_doit,				// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_dummy_doit,				// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESSED_INCOMING_PREROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_processed_incoming_prerouting,	// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESSED_INCOMING_POSTROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_processed_incoming_postrouting,	// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESSED_OUTGOING_PREROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_processed_outgoing_prerouting,	// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	}, {
		.cmd	= SUPERMAN_CMD_PROCESSED_OUTGOING_POSTROUTING,	// The command
		.flags	= 0,						// No flags
		.policy	= superman_genl_pol,				// No attributes, therefore, no policy
		.doit	= superman_processed_outgoing_postrouting,	// No do it handler (in the kernel)
		.dumpit = NULL,						// No dumpit handler
	},
};


void InvokeIncomingPrerouting(struct sk_buff* skb);
void InvokeIncomingPostrouting(struct sk_buff* skb);
void InvokeOutgoingPrerouting(struct sk_buff* skb);
void InvokeOutgoingPostrouting(struct sk_buff* skb);

#else

void InvokeSupermanDiscoveryRequest();

#endif

#endif

