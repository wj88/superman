#include "netlink.h"


#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>

#else

//sudo apt-get install libnl-3-dev libnl-genl-3-dev
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

#endif

#if __KERNEL__

int superman_send_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	SendDiscoveryRequest();
	return 0;
}

int superman_processed_incoming_prerouting(struct sk_buff *skb_msg, struct genl_info *info)
{

	return 0;
}

int superman_processed_incoming_postrouting(struct sk_buff *skb_msg, struct genl_info *info)
{

	return 0;
}

int superman_processed_outgoing_prerouting(struct sk_buff *skb_msg, struct genl_info *info)
{

	return 0;
}

int superman_processed_outgoing_postrouting(struct sk_buff *skb_msg, struct genl_info *info)
{

	return 0;
}

#else

bool is_superman_packet(short protocol)
{
	// Does this IPv4 packet contain superman payload?
	return (protocol == SUPERMAN_PROTOCOL_NUM);
}

int superman_process_incoming_prerouting(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{

	return NL_OK;
}

int superman_process_incoming_postrouting(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{

	return NL_OK;
}

int superman_process_outgoing_prerouting(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{

	return NL_OK;
}

int superman_process_outgoing_postrouting(int ifindex, int src_addr, int dst_addr, short protocol, int payload_len, void* payload)
{

	return NL_OK;
}

#endif

#ifndef __KERNEL__

struct nl_sock* sk;
int superman_family_id;
int superman_mc_group_id;

struct nl_msg* generate_message(int cmd)
{
	// Construct a new message
	struct nl_msg* msg = nlmsg_alloc();

	// Add the Generic Netlink header to the netlink message.
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, superman_family_id, 0, 0, cmd, 0);

	return msg;
}

void send_message(struct nl_msg* msg)
{
	// Send the message over the netlink socket
	nl_send_auto(sk, msg);

	// Cleanup
	nlmsg_free(msg);
}


int superman_netlink_callback(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = NULL;

	nlh = nlmsg_hdr(msg);
	if(!nlh) {
		syslog(LOG_ERR, "SUPERMAN: Failed to get message header.\n");
		return NL_SKIP;
	}

	if(!genlmsg_valid_hdr(nlh, 0)) {
		syslog(LOG_ERR, "SUPERMAN: Failed to validate generic netlink header.\n");
		return NL_SKIP;
	}

	struct genlmsghdr *ghdr;
	ghdr = nlmsg_data(nlh);

	// We want to filter our the commands we want to process.
	switch(ghdr->cmd) {
		case SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING:
		case SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING:
		case SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING:
		case SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING:
			break;
		default:
			return NL_SKIP;
			break;
	}

	// Parse the message, grabbing the attribute information.
	struct nlattr* attrs[SUPERMAN_ATTR_MAX + 1];
	if(genlmsg_parse(nlh, 0, attrs, SUPERMAN_ATTR_MAX, superman_genl_pol) < 0) {
		syslog(LOG_ERR, "SUPERMAN: Failed to parse netlink message\n");
		return NL_SKIP;
	}

	int ifindex = nla_get_u32(attrs[SUPERMAN_ATTR_IFINDEX]);
	int src_addr = nla_get_u32(attrs[SUPERMAN_ATTR_SRC_ADDR]);
	int dst_addr = nla_get_u32(attrs[SUPERMAN_ATTR_DST_ADDR]);
	short protocol = nla_get_u16(attrs[SUPERMAN_ATTR_PROTOCOL]);
	int payload_len = nla_len(attrs[SUPERMAN_ATTR_PAYLOAD]);
	void* payload = nla_data(attrs[SUPERMAN_ATTR_PAYLOAD]);

	switch(ghdr->cmd) {

		case SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING:
			return superman_process_incoming_prerouting(ifindex, src_addr, dst_addr, protocol, payload_len, payload);
			break;

		case SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING:
			return superman_process_incoming_postrouting(ifindex, src_addr, dst_addr, protocol, payload_len, payload);
			break;

		case SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING:
			return superman_process_outgoing_prerouting(ifindex, src_addr, dst_addr, protocol, payload_len, payload);
			break;

		case SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING:
			return superman_process_outgoing_postrouting(ifindex, src_addr, dst_addr, protocol, payload_len, payload);
			break;
	}

	return NL_OK;
}

void InvokeSupermanDiscoveryRequest()
{
	struct nl_msg *msg = generate_message(SUPERMAN_SEND_DISCOVERY_REQUEST);
	// We have no data to add, otherwise it would be injected here.
	send_message(msg);
}

#else

bool send_message(int cmd, struct sk_buff* src_skb)
{
	// Source IP message vars
	struct iphdr* iph;
	int payload_len;
	void* payload;

	// New netlink message vars
	struct sk_buff* skb.
	void* msg;

	iph = ip_hdr(src_skb);
	payload_len = iph->tot_len - (iph->ihl * 4);
	payload = ((void*)iph) + (iph->ihl * 4);

	skb = nlmsg_alloc();
	if(!skb) {
		printk(KERN_ERR "SUPERMAN: Failed to construct a message");
		return NULL;
	}

	// Add the Generic Netlink header to the netlink message.
	msg = genlmsg_put(skb, 
	                  0,				// PID is whatever
	                  0,				// Sequence number (don't care)
	                  &superman_genl_family,	// Pointer to family struct
	                  0,				// Flags
	                  cmd				// Generic netlink command 
	                  );
	if(!msg) {
		printk(KERN_ERR "SUPERMAN: Failed to create a message");
		return false;
	}

	// Put the attributes data into the message
	if(nla_put_u32(skb, SUPERMAN_ATTR_IFINDEX, src_skb->dev->ifindex) ||
	   nla_put_u32(skb, SUPERMAN_ATTR_SRC_ADDR, iph->saddr) ||
	   nla_put_u32(skb, SUPERMAN_ATTR_DST_ADDR, iph->daddr) ||
	   nla_put_u16(skb, SUPERMAN_ATTR_PROTOCOL, iph->protocol) ||
	   nla_put(skb, SUPERMAN_ATTR_PAYLOAD, payload_len, payload)) {
		printk(KERN_ERR "SUPERMAN: Failed to put data into the message");
		genlmsg_cancel(skb, msg);
		return false;
	}

	// Finish the message
	genlmsg_end(skb, msg);

	// Attemp to send the message.
	// If error - fail.
	// ESRCH is "forever alone" case - no one is listening for our messages 
	// and it's ok, since userspace daemon can be unloaded.
	rc = genlmsg_multicast_allns(skb, 0, superman_mc_group.id, GFP_KERNEL);
	if(rc && rc != -ESRCH) {
		printk(KERN_ERR "SUPERMAN: Failed to send the message");
		return false;
	}

	// Success
	return true;
}

void InvokeIncomingPrerouting(struct sk_buff* skb)
{
	send_message(SUPERMAN_CMD_PROCESS_INCOMING_PREROUTING, skb);
}

void InvokeIncomingPostrouting(struct sk_buff* skb)
{
	send_message(SUPERMAN_CMD_PROCESS_INCOMING_POSTROUTING, skb);
}

void InvokeOutgoingPrerouting(struct sk_buff* skb)
{
	send_message(SUPERMAN_CMD_PROCESS_OUTGOING_PREROUTING, skb);
}

void InvokeOutgoingPostrouting(struct sk_buff* skb)
{
	send_message(SUPERMAN_CMD_PROCESS_OUTGOING_POSTROUTING, skb);
}

#endif

bool InitNetlink(void)
{
#ifdef __KERNEL__

	int rc;

	rc = genl_register_family_with_ops(&superman_genl_family, superman_ops);
	if(rc) {
		printk(KERN_ERR "SUPERMAN: Failed to register the Generic Netlink family.");
		return false;
	}

	rc = genl_register_mc_group(&superman_genl_family, &superman_mc_group);
	if(rc) {
		printk(KERN_ERR "SUPERMAN: Failed to register the generic netlink multicast group.");
		genl_unregister_family(&superman_genl_family);
		return false;
	}

	return true;

#else

	// Create a netlink socket and connect to Generic Netlink
	sk = nl_socket_alloc();
	if(!sk) {
		printf("SUPERMAN: Failed to allocate netlink socket.\n");
		return false;
	}

	// Disable sequence number checking
	nl_socket_disable_seq_check(sk);

	// Provide the method used for multicast callbacks
	rc = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, superman_netlink_callback, NULL);
	if(rc < 0) {
		printf("SUPERMAN: Failed to modify netlink socket callback.\n");
		nl_sock_cleanup();
		return false;
	}

	rc = genl_connect(sk);
	if(rc < 0) {
		printf("SUPERMAN: Failed to connect to generic netlink.\n");
		nl_sock_cleanup();
		return false;	
	}

	// Find the SUPERMAN family identifier.
	superman_family_id = genl_ctrl_resolve(sk, SUPERMAN_GENL_FAMILY_NAME);
	if(superman_family_id < 0) {
		printf("SUPERMAN: Failed to resolve netlink family name. Is the SUPERMAN kernel module loaded?\n");
		nl_sock_cleanup();
		return false;
	}

	superman_mc_group_id = genl_ctrl_resolve_grp(sk, SUPERMAN_GENL_FAMILY_NAME, SUPERMAN_GENL_GROUP_NAME );
	if(superman_mc_group_id < 0) {
		printf("SUPERMAN: Failed to resolve netlink group name.\n");
		nl_sock_cleanup();
		return false;
	}

	rc = nl_socket_add_memberships(sk, superman_mc_group_id, 0);
	if(rc < 0) {
		printf("SUPERMAN: Failed to add multicast group membership.\n");
		nl_sock_cleanup();
		return false;
	}

#endif
}

void DeInitNetlink(void)
{
#ifdef __KERNEL__

	if(superman_genl_family.id) {
		genl_unregister_family(&superman_genl_family);
		superman_genl_family.id = 0;
	}

#else

	if(sk) {
		nl_socket_free(sk);
		sk = NULL;
	}

#endif
}

