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

#define K_SUPERMAN_FAMILYNAME "K_SUPERMAN"
#define D_SUPERMAN_FAMILYNAME "D_SUPERMAN"

enum {
	SUPERMAN_ATTR_ADDR,
	SUPERMAN_ATTR_MSG_LEN,
	SUPERMAN_ATTR_MSG,
	__SUPERMAN_ATTR_MAX,
#define SUPERMAN_ATTR_MAX (__SUPERMAN_ATTR_MAX - 1)
};


enum {
	K_SUPERMAN_DISCOVERY_REQUEST,
#define K_SUPERMAN_DISCOVERY_REQUEST K_SUPERMAN_DISCOVERY_REQUEST
	__K_SUPERMAN_MAX,
#define K_SUPERMAN_MAX __K_SUPERMAN_MAX
};

enum {
	D_SUPERMAN_CERTIFICATE_EXCHANGE,
#define D_SUPERMAN_CERTIFICATE_EXCHANGE D_SUPERMAN_CERTIFICATE_EXCHANGE

	D_SUPERMAN_AUTHENTICATED_SK_REQUEST,
#define D_SUPERMAN_AUTHENTICATED_SK_REQUEST D_SUPERMAN_AUTHENTICATED_SK_REQUEST

	D_SUPERMAN_AUTHENTICATED_SK_RESPONSE,
#define D_SUPERMAN_AUTHENTICATED_SK_RESPONSE D_SUPERMAN_AUTHENTICATED_SK_RESPONSE

	D_SUPERMAN_SK_INVALIDATE,
#define D_SUPERMAN_SK_INVALIDATE D_SUPERMAN_SK_INVALIDATE

	D_SUPERMAN_BROADCAST_KEY_EXCHANGE,
#define D_SUPERMAN_BROADCAST_KEY_EXCHANGE D_SUPERMAN_BROADCAST_KEY_EXCHANGE

	D_SUPERMAN_ENCRYPT_P2P,
#define D_SUPERMAN_ENCRYPT_P2P D_SUPERMAN_ENCRYPT_P2P

	D_SUPERMAN_DECRYPT_P2P,
#define D_SUPERMAN_DECRYPT_P2P D_SUPERMAN_DECRYPT_P2P

	D_SUPERMAN_ENCRYPT_BROADCAST,
#define D_SUPERMAN_ENCRYPT_BROADCAST D_SUPERMAN_ENCRYPT_BROADCAST

	D_SUPERMAN_DECRYPT_BROADCAST,
#define D_SUPERMAN_DECRYPT_BROADCAST D_SUPERMAN_DECRYPT_BROADCAST

	__D_SUPERMAN_MAX,
#define D_SUPERMAN_MAX __D_SUPERMAN_MAX
};

#define K_SUPERMAN_DISCOVERY_REQUEST_NAME		"Discovery Request"
#define D_SUPERMAN_CERTIFICATE_EXCHANGE_NAME		"Certificate Exchange"
#define D_SUPERMAN_AUTHENTICATED_SK_REQUEST_NAME	"Authenticated SK Request"
#define D_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME	"Authenticated SK Response"
#define D_SUPERMAN_SK_INVALIDATE_NAME			"SK Invalidate"
#define D_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME		"Broadcast Key Exchange"
#define D_SUPERMAN_ENCRYPT_P2P_NAME			"Encrypt P2P"
#define D_SUPERMAN_DECRYPT_P2P_NAME			"Decrypt P2P"
#define D_SUPERMAN_ENCRYPT_BROADCAST_NAME		"Encrypt Broadcast"
#define D_SUPERMAN_DECRYPT_BROADCAST_NAME		"Decrypt Broadcast"

static struct {
	int type;
	char *name;
} k_typenames[K_SUPERMAN_MAX] = {
	{ K_SUPERMAN_DISCOVERY_REQUEST,		K_SUPERMAN_DISCOVERY_REQUEST_NAME		},
};

static struct {
	int type;
	char *name;
} d_typenames[D_SUPERMAN_MAX] = {
	{ D_SUPERMAN_CERTIFICATE_EXCHANGE,	D_SUPERMAN_CERTIFICATE_EXCHANGE_NAME		},
	{ D_SUPERMAN_AUTHENTICATED_SK_REQUEST,	D_SUPERMAN_AUTHENTICATED_SK_REQUEST_NAME	},
	{ D_SUPERMAN_AUTHENTICATED_SK_RESPONSE,	D_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME	},
	{ D_SUPERMAN_SK_INVALIDATE,		D_SUPERMAN_SK_INVALIDATE_NAME			},
	{ D_SUPERMAN_BROADCAST_KEY_EXCHANGE,	D_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME		},
	{ D_SUPERMAN_ENCRYPT_P2P,		D_SUPERMAN_ENCRYPT_P2P_NAME			},
	{ D_SUPERMAN_DECRYPT_P2P,		D_SUPERMAN_DECRYPT_P2P_NAME			},
	{ D_SUPERMAN_ENCRYPT_BROADCAST,		D_SUPERMAN_ENCRYPT_BROADCAST_NAME		},
	{ D_SUPERMAN_DECRYPT_BROADCAST,		D_SUPERMAN_DECRYPT_BROADCAST_NAME		},
};

static inline char* k_superman_msg_type_to_str(int type)
{
	int i;
	for (i = 0; i < K_SUPERMAN_MAX; i++) {
		if (type == k_typenames[i].type) {
			return k_typenames[i].name;
		}
	}
	return "Unknown message type";
}

static inline char* d_superman_msg_type_to_str(int type)
{
	int i;
	for (i = 0; i < D_SUPERMAN_MAX; i++) {
		if (type == d_typenames[i].type) {
			return d_typenames[i].name;
		}
	}
	return "Unknown message type";
}

/*
// A SUPERMAN discovery request message.
static struct nla_policy superman_discovery_request_genl_policy[1] = {
};

// A SUPERMAN certificate exchange message.
typedef struct superman_certificate_exchange_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// cert
} superman_certificate_exchange_msg_t;
static struct nla_policy superman_certificate_exchange_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};


// A SUPERMAN authenticated SK request message.
typedef struct superman_authenticated_sk_request_msg {
	u_int32_t	addr;
} superman_authenticated_sk_request_msg_t;
static struct nla_policy superman_authenticated_sk_request_genl_policy[2] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
};


// A SUPERMAN authenticated SK response message.
typedef struct superman_authenticated_sk_response_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// sk
} superman_authenticated_sk_response_msg_t;
static struct nla_policy superman_authenticated_sk_response_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};


// A SUPERMAN SK invalidate message.
typedef struct superman_sk_invalidate_msg {
	u_int32_t	addr;
} superman_sk_invalidate_msg_t;
static struct nla_policy superman_sk_invalidate_genl_policy[2] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
};


// A SUPERMAN broadcast key exchange message.
typedef struct superman_broadcast_key_exchange_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// broadcast key
} superman_broadcast_key_exchange_msg_t;
static struct nla_policy superman_broadcast_key_exchange_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};


// A SUPERMAN encrypt p2p message.
typedef struct superman_encrypt_p2p_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// non-encrypted data
} superman_encrypt_p2p_msg_t;
static struct nla_policy superman_encrypt_p2p_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};


// A SUPERMAN decrypt p2p message.
typedef struct superman_decrypt_p2p_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// encrypted data
} superman_decrypt_p2p_msg_t;
static struct nla_policy superman_decrypt_p2p_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};

// A SUPERMAN encrypt broadcast message.
typedef struct superman_encrypt_broadcast_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// non-encrypted data
} superman_encrypt_broadcast_msg_t;
static struct nla_policy superman_encrypt_broadcast_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};


// A SUPERMAN decrypt broadcast message.
typedef struct superman_decrypt_broadcast_msg {
	u_int32_t	addr;
	u_int32_t	msg_len;
	char*		msg;		// encrypted data
} superman_decrypt_broadcast_msg_t;
static struct nla_policy superman_decrypt_broadcast_genl_policy[4] = {
	[SUPERMAN_ATTR_ADDR]	=	{ .type = NLA_NUL_STRING },
	[SUPERMAN_ATTR_MSG_LEN] = 	{ .type = NLA_U32 },
	[SUPERMAN_ATTR_MSG]	=	{ .type = NLA_UNSPEC },
};
*/

#if __kernel__

int superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	SendDiscoveryRequest();
	return 0;
}

#else

int superman_certificate_exchange(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_authenticated_sk_request(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_authenticated_sk_response(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_sk_invalidate(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_broadcast_key_exchange(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_encrypt_p2p(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_decrypt_p2p(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_encrypt_broadcast(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

int superman_decrypt_broadcast(struct nl_cache_ops *ops, struct genl_cmd *cmd, struct genl_info *info, void *arg)
{
	return 0;
}

#endif

#ifdef __kernel__
static struct genl_family superman_genl_family = {
	.id = 0, 	// GENL_ID_GENERATE = 0
	.hdrsize = 0,
	.name = K_SUPERMAN_FAMILYNAME,
	.version = 1,
	.maxattr = SUPERMAN_ATTR_MAX,
};

static struct genl_ops superman_ops[K_SUPERMAN_MAX] = {
	{
		.cmd = K_SUPERMAN_DISCOVERY_REQUEST,
		.flags = 0,
		.policy = 0, // superman_discovery_request_genl_policy,
		.doit = superman_discovery_request,
		.dumpit = NULL,
	},
};
#else
static struct genl_cmd superman_cmds[] = {
	{
		.c_id       	= D_SUPERMAN_CERTIFICATE_EXCHANGE,
		.c_name     	= D_SUPERMAN_CERTIFICATE_EXCHANGE_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0,
		.c_msg_parser   = superman_certificate_exchange,
	}, {
		.c_id 		= D_SUPERMAN_AUTHENTICATED_SK_REQUEST,
		.c_name     	= D_SUPERMAN_AUTHENTICATED_SK_REQUEST_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_authenticated_sk_request_genl_policy,
		.c_msg_parser   = superman_authenticated_sk_request,
	}, {
		.c_id 		= D_SUPERMAN_AUTHENTICATED_SK_RESPONSE,
		.c_name     	= D_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_authenticated_sk_response_genl_policy,
		.c_msg_parser   = superman_authenticated_sk_response,
	}, {
		.c_id 		= D_SUPERMAN_SK_INVALIDATE,
		.c_name     	= D_SUPERMAN_SK_INVALIDATE_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_sk_invalidate_genl_policy,
		.c_msg_parser   = superman_sk_invalidate,
	}, {
		.c_id 		= D_SUPERMAN_BROADCAST_KEY_EXCHANGE,
		.c_name     	= D_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_broadcast_key_exchange_genl_policy,
		.c_msg_parser   = superman_broadcast_key_exchange,
	}, {
		.c_id 		= D_SUPERMAN_ENCRYPT_P2P,
		.c_name     	= D_SUPERMAN_ENCRYPT_P2P_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_encrypt_p2p_genl_policy,
		.c_msg_parser   = superman_encrypt_p2p,
	}, {
		.c_id 		= D_SUPERMAN_DECRYPT_P2P,
		.c_name     	= D_SUPERMAN_DECRYPT_P2P_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_decrypt_p2p_genl_policy,
		.c_msg_parser   = superman_decrypt_p2p,
	}, {
		.c_id 		= D_SUPERMAN_ENCRYPT_BROADCAST,
		.c_name     	= D_SUPERMAN_ENCRYPT_BROADCAST_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_encrypt_broadcast_genl_policy,
		.c_msg_parser   = superman_encrypt_broadcast,
	}, {
		.c_id 		= D_SUPERMAN_DECRYPT_BROADCAST,
		.c_name     	= D_SUPERMAN_DECRYPT_BROADCAST_NAME,
		.c_maxattr  	= SUPERMAN_ATTR_MAX,
		.c_attr_policy  = 0, // superman_decrypt_broadcast_genl_policy,
		.c_msg_parser   = superman_decrypt_broadcast,
	},
};

static struct genl_ops superman_ops = {
	.o_name		= D_SUPERMAN_FAMILYNAME,
	.o_hdrsize	= 0,
	.o_cmds         = superman_cmds,
	.o_ncmds        = D_SUPERMAN_MAX, // ARRAY_SIZE(superman_cmds),
};
#endif




/*

#ifdef __KERNEL__

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

// Create a raw netlink socket and bind
static int create_nl_socket(int protocol, int groups)
{
	socklen_t addr_len;
	int fd;
	struct sockaddr_nl local;
	
	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		close(fd);
		return -1;
	}
	
	return fd;
}

// Send netlink message to kernel
bool sendto_fd(int nl_sd, const char *buf, int bufLen)
{
        struct sockaddr_nl nladdr;
        int r;
        
        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        
        while ((r = sendto(nl_sd, buf, bufLen, 0, (struct sockaddr *) &nladdr, sizeof(nladdr))) < bufLen) {
                if (r > 0) {
                        buf += r;
                        bufLen -= r;
                } else if (errno != EAGAIN)
                        return false;
        }
        return true;
}

// Probe the controller in genetlink to find the family id
// for the family id
int get_family_id(int nl_sd)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} family_req;
	
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} ans;

	int id;
	struct nlattr *na;
	int rep_len;

	// Get family name
	family_req.n.nlmsg_type = GENL_ID_CTRL;
	family_req.n.nlmsg_flags = NLM_F_REQUEST;
	family_req.n.nlmsg_seq = 0;
	family_req.n.nlmsg_pid = getpid();
	family_req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	family_req.g.cmd = CTRL_CMD_GETFAMILY;
	family_req.g.version = 0x1;
	
	na = (struct nlattr *) GENLMSG_DATA(&family_req);
	na->nla_type = CTRL_ATTR_FAMILY_NAME;

// If we're a kernel module, we're trying to connect to the daemon.
#ifdef __KERNEL__
	na->nla_len = strlen(D_SUPERMAN_FAMILYNAME) + 1 + NLA_HDRLEN;
	strcpy((char*)NLA_DATA(na), D_SUPERMAN_FAMILYNAME);
// If we're the daemon, we're trying to connect to the kernel module.
#else
	na->nla_len = strlen(K_SUPERMAN_FAMILYNAME) + 1 + NLA_HDRLEN;
	strcpy((char*)NLA_DATA(na), K_SUPERMAN_FAMILYNAME);
#endif
	
	family_req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	if (sendto_fd(nl_sd, (char *) &family_req, family_req.n.nlmsg_len) < 0)
		return false;
    
	rep_len = recv(nl_sd, &ans, sizeof(ans), 0);
	if (rep_len < 0){
		perror("recv");
		return -1;
	}

	// Validate response message
	if (!NLMSG_OK((&ans.n), rep_len)){
		fprintf(stderr, "invalid reply message\n");
		return -1;
	}

	if (ans.n.nlmsg_type == NLMSG_ERROR) { // error
		fprintf(stderr, "received error\n");
		return -1;
	}

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
    	}

	return id;
}

#endif

*/

#ifndef __KERNEL__

void InvokeSupermanDiscoveryRequest()
{
	struct nl_sock* sk;
	struct nl_msg *msg;
	int superman_family_id;

	// Create a netlink socket and connect to Generic Netlink
	sk = nl_socket_alloc();
	genl_connect(sk);

	// Find the SUPERMAN family identifier.
	superman_family_id = genl_ctrl_resolve(sk, "SUPERMAN");

	if(superman_family_id >= 0)
	{
		// Construct a new message
		msg = nlmsg_alloc();

		// Add the Generic Netlink header to the netlink message.
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, superman_family_id, 0, 0, K_SUPERMAN_DISCOVERY_REQUEST, 0);

		// We have no data to add.

		// Send the message over the netlink socket
		nl_send_auto(sk, msg);

		// Cleanup
		nlmsg_free(msg);
	}
	else
		printf("No SUPERMAN netlink family found. Is the SUPERMAN kernel module loaded?\n");

	// Cleanup
	nl_socket_free(sk);
}

#else


// If data != NULL the caller is responsible for cleaning up memory!
bool InvokeCertificateRequest(void** data, int* data_size)
{
	int nl_sd;
	int family_id;

	*data = NULL;
	*data_size = 0;

	nl_sd = create_nl_socket(NETLINK_GENERIC, 0);
	if(nl_sd < 0) {
		printf("SUPERMAN: create_nl_socket failure.\n");
		return;
	}
	family_id = get_family_id(nl_sd);
	if(family_id < 0) {
		printf("SUPERMAN: netlink family lookup failed. Is the SUPERMAN kernel module loaded?\n");
		goto cleanup;
	}



	struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[256];
        } ans;

        struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[256];
        } req;
        struct nlattr *na;

	// Send command needed
        req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        req.n.nlmsg_type = family_id;
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_seq = 0;
        req.n.nlmsg_pid = getpid();
        req.g.cmd = K_SUPERMAN_CERTIFICATE_REQUEST;

	// Compose message
	// na = (struct nlattr *) GENLMSG_DATA(&req);
        // na->nla_type = 1; // DOC_EXMPL_A_MSG
        // char * message = "hello world!"; //message
        // int mlength = 14;
        // na->nla_len = mlength+NLA_HDRLEN; //message length
        // memcpy(NLA_DATA(na), message, mlength);
        // req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	// Send message
	struct sockaddr_nl nladdr;
        int r;
        
        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
    
	r = sendto(nl_sd, (char *)&req, req.n.nlmsg_len, 0, (struct sockaddr *) &nladdr, sizeof(nladdr));
	
	rep_len = recv(nl_sd, &ans, sizeof(ans), 0);
        // Validate response message
        if (ans.n.nlmsg_type == NLMSG_ERROR) { // error
                printf("SUPERMAN: Error received NACK - leaving\n");
		goto cleanup;
        }
        if (rep_len < 0) {
               	printf("SUPERMAN: Error receiving reply message via Netlink\n");
		goto cleanup;
        }
        if (!NLMSG_OK((&ans.n), rep_len)) {
               	printf("SUPERMAN: Invalid reply message received via Netlink\n");
		goto cleanup;
	}

	
        *data_size = GENLMSG_PAYLOAD(&ans.n);
        na = (struct nlattr *) GENLMSG_DATA(&ans);
	*data = kmalloc(rep_len, GFP_ATOMIC);
	memcpy(*data, NLA_DATA(na), *data_size);

cleanup:
        close(nl_sd);
	return *data != NULL;
}

#endif

void InitNetlink(void)
{
#ifdef __KERNEL__
	genl_register_family_with_ops(&superman_genl_family, superman_ops);
#else
	genl_register_family(&superman_ops);	
#endif
}

void DeInitNetlink(void)
{
#ifdef __KERNEL__
	genl_unregister_family(&superman_genl_family);
#else
	genl_unregister_family(&superman_ops);	
#endif
}

