#include "netlink.h"
#include "processor.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>
#include "security_table.h"


// Define our prototypes to prevent kernel build warnings
int k_load_node_certificate_and_secure_interface(struct sk_buff *skb_msg, struct genl_info *info);
int k_secure_interface(struct sk_buff *skb_msg, struct genl_info *info);
int k_secure_interface_by_name(struct sk_buff *skb_msg, struct genl_info *info);
int k_unsecure_interface(struct sk_buff *skb_msg, struct genl_info *info);
int k_unsecure_interface_by_name(struct sk_buff *skb_msg, struct genl_info *info);
//int k_update_superman_interface_table_entry(struct sk_buff *skb_msg, struct genl_info *info);
int k_unload_all(struct sk_buff *skb_msg, struct genl_info *info);
int k_update_superman_security_table_entry(struct sk_buff *skb_msg, struct genl_info *info);
int k_update_superman_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info);
int k_trigger_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_certificate_request(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_certificate_exchange(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_certificate_exchange_with_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_broadcast_key_exchange(struct sk_buff *skb_msg, struct genl_info *info);
int k_send_superman_sk_invalidate(struct sk_buff *skb_msg, struct genl_info *info);
int d_load_node_certificate_then_secure_interface(struct sk_buff *skb_msg, struct genl_info *info);
int d_raise_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info);
int d_raise_new_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_certificate_request(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_certificate_exchange(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_certificate_exchange_with_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_authenticated_sk_response(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_sk_invalidate(struct sk_buff *skb_msg, struct genl_info *info);
int d_received_superman_broadcast_key_exchange(struct sk_buff *skb_msg, struct genl_info *info);


// // This function is defined in  net_namespace.h but the symbol is not exported

// struct net *get_net_ns_by_id(const struct net *net, int id)
// {
// 	struct net *peer;

// 	if (id < 0)
// 		return NULL;

// 	rcu_read_lock();
// 	peer = idr_find(&net->netns_ids, id);
// 	if (peer)
// 		peer = maybe_get_net(peer);
// 	rcu_read_unlock();

// 	return peer;
// }


// struct net* GetNetFromNSID(uint32_t netns_id)
// {
//     struct net *caller_net = get_net(current->nsproxy->net_ns);
//     struct net *target_net = NULL;

//     for_each_net(target_net) {
//         if (peernet2id(caller_net, target_net) == netns_id) {
//             get_net(target_net);  // Take a reference
//             break;
//         }
//     }

//     put_net(caller_net);  // Release caller reference
//     return target_net;    // NULL if not found
// }

// int GetNSIDFromNet(struct net* net)
// {
//     struct net *caller_net = get_net(current->nsproxy->net_ns);
//     int nsid = peernet2id(caller_net, net);
//     put_net(caller_net);
//     return nsid;
// }


#else
//sudo apt-get install libnl-3-dev libnl-genl-3-dev
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

static struct nl_sock *nlsk = NULL;
static int superman_mc_group_id = -1;
struct nl_cache *genl_cache = NULL;
int superman_family_id = -1;										\

#endif

bool netlink_loaded = false;

#define K_SUPERMAN_FAMILY_NAME		"SUPERMAN"		// Maximum 16 characters (inc. NULL terminator)
#define K_SUPERMAN_MC_GROUP_NAME	"SUPERMAN_GROUP"	// Maximum 16 characters (inc. NULL terminator)

enum {
// Local Kernel state updating from the Daemon
	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE,
#define K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE

	K_SECURE_INTERFACE,
#define K_SECURE_INTERFACE K_SECURE_INTERFACE

	K_SECURE_INTERFACE_BY_NAME,
#define K_SECURE_INTERFACE_BY_NAME K_SECURE_INTERFACE_BY_NAME

	K_UNSECURE_INTERFACE,
#define K_UNSECURE_INTERFACE K_UNSECURE_INTERFACE

	K_UNSECURE_INTERFACE_BY_NAME,
#define K_UNSECURE_INTERFACE_BY_NAME K_UNSECURE_INTERFACE_BY_NAME

// 	K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY,
// #define K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY

	K_UNLOAD_ALL,
#define K_UNLOAD_ALL K_UNLOAD_ALL

	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY,
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY

	K_UPDATE_SUPERMAN_BROADCAST_KEY,
#define K_UPDATE_SUPERMAN_BROADCAST_KEY K_UPDATE_SUPERMAN_BROADCAST_KEY

// Daemon instructing Kernel to send packets
	K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST,
#define K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST

	K_SEND_SUPERMAN_DISCOVERY_REQUEST,
#define K_SEND_SUPERMAN_DISCOVERY_REQUEST K_SEND_SUPERMAN_DISCOVERY_REQUEST

	K_SEND_SUPERMAN_CERTIFICATE_REQUEST,
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST K_SEND_SUPERMAN_CERTIFICATE_REQUEST

	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE,
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE

	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY

	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE,
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE

	K_SEND_SUPERMAN_SK_INVALIDATE,
#define K_SEND_SUPERMAN_SK_INVALIDATE K_SEND_SUPERMAN_SK_INVALIDATE

// Kernel instructing the Daemon of a specialist received packet
	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE,
#define D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE

	D_RAISE_SUPERMAN_DISCOVERY_REQUEST,
#define D_RAISE_SUPERMAN_DISCOVERY_REQUEST D_RAISE_SUPERMAN_DISCOVERY_REQUEST

	D_RAISE_NEW_BROADCAST_KEY,
#define D_RAISE_NEW_BROADCAST_KEY D_RAISE_NEW_BROADCAST_KEY

	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST,
#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST

	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST

	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE

	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY

	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE,
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE

	D_RECEIVED_SUPERMAN_SK_INVALIDATE,
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE D_RECEIVED_SUPERMAN_SK_INVALIDATE

	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE,
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE

	__SUPERMAN_MAX,
#define SUPERMAN_MAX __SUPERMAN_MAX
};

#define K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_NAME					"Request the loading of a node certificate and securing of a network interface"
#define K_SECURE_INTERFACE_NAME												"Request the securing of a network interface"
#define K_SECURE_INTERFACE_NAME_BY_NAME										"Request the securing of a network interface by name"
#define K_UNSECURE_INTERFACE_NAME											"Request the unsecuring of a network interface"
#define K_UNSECURE_INTERFACE_NAME_BY_NAME									"Request the unsecuring of a network interface by name"

//#define K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_NAME						"Update an interface table entry"
#define K_UNLOAD_ALL_NAME													"Unload all tables (interfaces, security and queue)"
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_NAME							"Update a security table entry"
#define K_UPDATE_SUPERMAN_BROADCAST_KEY_NAME								"Update the broadcast Key"

#define K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_NAME							"Trigger a discovery request"
#define K_SEND_SUPERMAN_DISCOVERY_REQUEST_NAME								"Send a discovery request"
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST_NAME							"Send a certificate request"
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_NAME							"Send a certificate exchange"
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME		"Send a certificate exchange (inc. broadcast key)"
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME							"Send a broadcast key exchange"
#define K_SEND_SUPERMAN_SK_INVALIDATE_NAME									"Send an SK invalidate"

#define D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_NAME					"Load the node certificate then secure the node"
#define D_RAISE_SUPERMAN_DISCOVERY_REQUEST_NAME								"Raise a discovery request"
#define D_RAISE_NEW_BROADCAST_KEY_NAME										"Raise a new broadcast key"
#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_NAME							"Received a discovery request"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_NAME						"Received a certificate request"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_NAME						"Received a certificate exchange"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME	"Received a certificate exchange (inc. broadcast key)"
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME					"Received an authenticated SK response"
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE_NAME								"Received an SK invalidate"
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME						"Received a broadcast key exchange"

#ifdef __KERNEL__
#define SUPERMAN_BINARY_MAXLEN .len = 8096
#else
#define SUPERMAN_BINARY_MAXLEN .minlen = 0, .maxlen = 8096
#endif
	

static struct {
	int type;
	char *name;
} superman_typenames[SUPERMAN_MAX+1] = {
	{ K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE,					K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_NAME					},
	{ K_SECURE_INTERFACE,											K_SECURE_INTERFACE_NAME												},
	{ K_SECURE_INTERFACE_BY_NAME,									K_SECURE_INTERFACE_NAME_BY_NAME										},
	{ K_UNSECURE_INTERFACE,											K_UNSECURE_INTERFACE_NAME											},
	{ K_UNSECURE_INTERFACE_BY_NAME,									K_UNSECURE_INTERFACE_NAME_BY_NAME									},
	// { K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY,					K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_NAME						},
	{ K_UNLOAD_ALL, 												K_UNLOAD_ALL_NAME													},
	{ K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY,						K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_NAME							},
	{ K_UPDATE_SUPERMAN_BROADCAST_KEY,								K_UPDATE_SUPERMAN_BROADCAST_KEY_NAME								},
	{ K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST,							K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_NAME							},
	{ K_SEND_SUPERMAN_DISCOVERY_REQUEST,							K_SEND_SUPERMAN_DISCOVERY_REQUEST_NAME								},
	{ K_SEND_SUPERMAN_CERTIFICATE_REQUEST,							K_SEND_SUPERMAN_CERTIFICATE_REQUEST_NAME							},
	{ K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE,							K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_NAME							},
	{ K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,		K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME		},
	{ K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE,						K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME							},
	{ K_SEND_SUPERMAN_SK_INVALIDATE,								K_SEND_SUPERMAN_SK_INVALIDATE_NAME									},
	{ D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE, 				D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_NAME					},
	{ D_RAISE_SUPERMAN_DISCOVERY_REQUEST,							D_RAISE_SUPERMAN_DISCOVERY_REQUEST_NAME								},
	{ D_RAISE_NEW_BROADCAST_KEY,									D_RAISE_NEW_BROADCAST_KEY_NAME										},
	{ D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST,						D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_NAME							},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST,						D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_NAME						},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE,						D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_NAME						},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME	},
	{ D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE,				D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME					},
	{ D_RECEIVED_SUPERMAN_SK_INVALIDATE,							D_RECEIVED_SUPERMAN_SK_INVALIDATE_NAME								},
	{ D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE,					D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME						},
};

static inline char* superman_msg_type_to_str(int type)
{
	int i;
	for (i = 0; i < SUPERMAN_MAX; i++) {
		if (type == superman_typenames[i].type) {
			return superman_typenames[i].name;
		}
	}
	return "Unknown message type";
}

// K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE
enum {
	__K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_FIRST = 0,
	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME,
	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME,
	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_INTERFACE_NAME,
	__K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_LAST,
};
#define K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_MIN (__K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_FIRST + 1)
#define K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_MAX (__K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_LAST - 1)
typedef struct k_load_node_certificate_and_secure_interface_msg {
	uint32_t		node_cert_filename_len;
	unsigned char*	node_cert_filename;
	uint32_t		node_privatekey_filename_len;
	unsigned char*	node_privatekey_filename;
	uint32_t		interface_name_len;
	unsigned char*	interface_name;
} k_load_node_certificate_and_secure_interface_msg_t;
static struct nla_policy k_load_node_certificate_and_secure_interface_genl_policy[K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_MAX + 1] = {
	[K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME]				=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME]			=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN 	},
	[K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_INTERFACE_NAME]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN 	},
};

// K_SECURE_INTERFACE
enum {
	__K_SECURE_INTERFACE_ATTR_FIRST = 0,
	K_SECURE_INTERFACE_ATTR_IFINDEX,
	__K_SECURE_INTERFACE_ATTR_LAST,
};
#define K_SECURE_INTERFACE_ATTR_MIN (__K_SECURE_INTERFACE_ATTR_FIRST + 1)
#define K_SECURE_INTERFACE_ATTR_MAX (__K_SECURE_INTERFACE_ATTR_LAST - 1)
typedef struct k_secure_interface_msg {
	uint32_t	ifindex;
} k_secure_interface_msg_t;
static struct nla_policy k_secure_interface_genl_policy[K_SECURE_INTERFACE_ATTR_MAX + 1] = {
	[K_SECURE_INTERFACE_ATTR_IFINDEX]								=	{ .type = NLA_U32	},
};

// K_SECURE_INTERFACE_BY_NAME
enum {
	__K_SECURE_INTERFACE_BY_NAME_ATTR_FIRST = 0,
	K_SECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME,
	__K_SECURE_INTERFACE_BY_NAME_ATTR_LAST,
};
#define K_SECURE_INTERFACE_BY_NAME_ATTR_MIN (__K_SECURE_INTERFACE_BY_NAME_ATTR_FIRST + 1)
#define K_SECURE_INTERFACE_BY_NAME_ATTR_MAX (__K_SECURE_INTERFACE_BY_NAME_ATTR_LAST - 1)
typedef struct k_secure_interface_by_name_msg {
	uint32_t		interface_name_len;
	unsigned char*	interface_name;
} k_secure_interface_by_name_msg_t;
static struct nla_policy k_secure_interface_by_name_genl_policy[K_SECURE_INTERFACE_BY_NAME_ATTR_MAX + 1] = {
	[K_SECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_UNSECURE_INTERFACE
enum {
	__K_UNSECURE_INTERFACE_ATTR_FIRST = 0,
	K_UNSECURE_INTERFACE_ATTR_IFINDEX,
	__K_UNSECURE_INTERFACE_ATTR_LAST,
};
#define K_UNSECURE_INTERFACE_ATTR_MIN (__K_UNSECURE_INTERFACE_ATTR_FIRST + 1)
#define K_UNSECURE_INTERFACE_ATTR_MAX (__K_UNSECURE_INTERFACE_ATTR_LAST - 1)
typedef struct k_unsecure_interface_msg {
	uint32_t	ifindex;
} k_unsecure_interface_msg_t;
static struct nla_policy k_unsecure_interface_genl_policy[K_UNSECURE_INTERFACE_ATTR_MAX + 1] = {
	[K_UNSECURE_INTERFACE_ATTR_IFINDEX]									=	{ .type = NLA_U32	},
};

// K_UNSECURE_INTERFACE_BY_NAME
enum {
	__K_UNSECURE_INTERFACE_BY_NAME_ATTR_FIRST = 0,
	K_UNSECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME,
	__K_UNSECURE_INTERFACE_BY_NAME_ATTR_LAST,
};
#define K_UNSECURE_INTERFACE_BY_NAME_ATTR_MIN (__K_UNSECURE_INTERFACE_BY_NAME_ATTR_FIRST + 1)
#define K_UNSECURE_INTERFACE_BY_NAME_ATTR_MAX (__K_UNSECURE_INTERFACE_BY_NAME_ATTR_LAST - 1)
typedef struct k_unsecure_interface_by_name_msg {
	uint32_t		interface_name_len;
	unsigned char*	interface_name;
} k_unsecure_interface_by_name_msg_t;
static struct nla_policy k_unsecure_interface_by_name_genl_policy[K_UNSECURE_INTERFACE_BY_NAME_ATTR_MAX + 1] = {
	[K_UNSECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY
// enum {
// 	__K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_FIRST = 0,
// 	K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_INTERFACE_NAME,
// 	K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MONITOR_FLAG,
// 	__K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_LAST,
// };
// #define K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MIN (__K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_FIRST + 1)
// #define K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MAX (__K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_LAST - 1)
// typedef struct k_update_superman_interface_table_entry_msg {
// 	uint32_t	interface_name_len;
// 	unsigned char*	interface_name;
// 	bool		monitor_flag;
// } k_update_superman_interface_table_entry_msg_t;
// static struct nla_policy k_update_superman_interface_table_entry_genl_policy[K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MAX + 1] = {
// 	[K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_INTERFACE_NAME]				=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
// 	[K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MONITOR_FLAG]				=	{ .type = NLA_FLAG	},
// };

// K_UNLOAD_ALL
enum {
	__K_UNLOAD_ALL_ATTR_FIRST = 0,
	__K_UNLOAD_ALL_ATTR_LAST,
};
#define K_UNLOAD_ALL_ATTR_MIN (__K_UNLOAD_ALL_ATTR_FIRST + 1)
#define K_UNLOAD_ALL_ATTR_MAX (__K_UNLOAD_ALL_ATTR_LAST - 1)
typedef struct k_unload_all_msg {
} k_unload_all_msg_t;
static struct nla_policy k_unload_all_genl_policy[K_UNLOAD_ALL_ATTR_MAX + 1] = {
};

// K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY
enum {
	__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FIRST = 0,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_IFINDEX,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_TIMESTAMP,
	__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_LAST,
};
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MIN (__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FIRST + 1)
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX (__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_LAST - 1)
typedef struct k_update_superman_security_table_entry_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint8_t			flag;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		ske_len;
	unsigned char*	ske;
	uint32_t		skp_len;
	unsigned char*	skp;
	int32_t			timestamp;
} k_update_superman_security_table_entry_msg_t;
static struct nla_policy k_update_superman_security_table_entry_genl_policy[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX + 1] = {
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_IFINDEX]					=	{ .type = NLA_U32		},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG] 						= 	{ .type = NLA_U8		},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK]						=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE]						=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP]						=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_TIMESTAMP]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_UPDATE_SUPERMAN_BROADCAST_KEY
enum {
	__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_FIRST = 0,
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_IFINDEX,
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SK,
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKE,
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKP,
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_OVERWRITE,
	__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_LAST,interface_
};
#define K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MIN (__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_FIRST + 1)
#define K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX (__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_LAST - 1)
typedef struct k_update_superman_broadcast_key_msg {
	uint32_t		ifindex;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		ske_len;
	unsigned char*	ske;
	uint32_t		skp_len;
	unsigned char*	skp;
	bool			overwrite;
} k_update_superman_broadcast_key_msg_t;
static struct nla_policy k_update_superman_broadcast_key_genl_policy[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX + 1] = {
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_IFINDEX]						=	{ .type = NLA_U32		},
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SK]							=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKE]							=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKP]							=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_OVERWRITE]					=	{ .type = NLA_FLAG		},
};

// K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST
enum {
	__K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST = 0,
	__K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST,
};
#define K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_MIN (__K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST + 1)
#define K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST - 1)
typedef struct k_trigger_superman_discovery_request_msg {
} k_trigger_superman_discovery_request_msg_t;
static struct nla_policy k_trigger_superman_discovery_request_genl_policy[K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
};

// K_SEND_SUPERMAN_DISCOVERY_REQUEST
enum {
	__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST = 0,
	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,
	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,
	__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST,
};
#define K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MIN (__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST - 1)
typedef struct k_send_superman_discovery_request_msg {
	uint32_t		ifindex;
	uint32_t		sk_len;
	unsigned char*	sk;
} k_send_superman_discovery_request_msg_t;
static struct nla_policy k_send_superman_discovery_request_genl_policy[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]					=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]							=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_SEND_SUPERMAN_CERTIFICATE_REQUEST
enum {
	__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_FIRST = 0,
	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX,
	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,
	__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_LAST,
};
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MIN (__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_LAST - 1)
typedef struct k_send_superman_certificate_request_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
} k_send_superman_certificate_request_msg_t;
static struct nla_policy k_send_superman_certificate_request_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX]					=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]						=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE
enum {
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_FIRST = 0,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_LAST,
};
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MIN (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_LAST - 1)
typedef struct k_send_superman_certificate_exchange_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		certificate_len;
	unsigned char*	certificate;
} k_send_superman_certificate_exchange_msg_t;
static struct nla_policy k_send_superman_certificate_exchange_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX]						=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]						=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY
enum {
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_FIRST = 0,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_LAST,
};
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MIN (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_LAST - 1)
typedef struct k_send_superman_certificate_exchange_with_broadcast_key_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		certificate_len;
	unsigned char*	certificate;
} k_send_superman_certificate_exchange_with_broadcast_key_msg_t;
static struct nla_policy k_send_superman_certificate_exchange_with_broadcast_key_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX]			=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]			=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]		=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE
enum {
	__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_FIRST = 0,
	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX,
	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,
	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_ONLY_IF_CHANGED,
	__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_LAST,
};
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MIN (__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX (__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_LAST - 1)
typedef struct k_send_superman_broadcast_key_exchange_msg {
	uint32_t		ifindex;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;
	bool			only_if_changed;
} k_send_superman_broadcast_key_exchange_msg_t;
static struct nla_policy k_send_superman_broadcast_key_exchange_genl_policy[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX]						=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_ONLY_IF_CHANGED]				=	{ .type = NLA_FLAG		},
};

// K_SEND_SUPERMAN_SK_INVALIDATE
enum {
	__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_FIRST = 0,
	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX,
	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,
	__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_LAST,
};
#define K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MIN (__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_FIRST + 1)
#define K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX (__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_LAST - 1)
typedef struct k_send_superman_sk_invalidate_msg {
	uint32_t	ifindex;
	uint32_t	address;
} k_send_superman_sk_invalidate_msg_t;
static struct nla_policy k_send_superman_sk_invalidate_genl_policy[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX]						=	{ .type = NLA_U32	},
	[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]						=	{ .type = NLA_U32	},
};

// D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE
enum {
	__D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_FIRST = 0,
	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_IFINDEX,
	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME,
	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME,
	__D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_LAST,
};
#define D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_MIN (__D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_FIRST + 1)
#define D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_MAX (__D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_LAST - 1)
typedef struct d_load_node_certificate_then_secure_interface_msg {
	uint32_t		ifindex;
	uint32_t		node_cert_filename_len;
	unsigned char*	node_cert_filename;
	uint32_t		node_privatekey_filename_len;
	unsigned char*	node_privatekey_filename;
} d_load_node_certificate_the_secure_interface_msg_t;
static struct nla_policy d_load_node_certificate_then_secure_interface_genl_policy[D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_MAX + 1] = {
	[D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_IFINDEX]					=	{ .type = NLA_U32		},
	[D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME]			=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME]		=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	}
};

// D_RAISE_SUPERMAN_DISCOVERY_REQUEST
enum {
	__D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST = 0,
	D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,
	__D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST,
};
#define D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_MIN (__D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST + 1)
#define D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST - 1)
typedef struct d_raise_superman_discovery_request_msg {
	uint32_t	ifindex;
} d_raise_superman_discovery_request_msg_t;
static struct nla_policy d_raise_superman_discovery_request_genl_policy[D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
	[D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]					=	{ .type = NLA_U32	},
};

// D_RAISE_NEW_BROADCAST_KEY
enum {
	__D_RAISE_NEW_BROADCAST_KEY_ATTR_FIRST = 0,
	D_RAISE_NEW_BROADCAST_KEY_ATTR_IFINDEX,
	__D_RAISE_NEW_BROADCAST_KEY_ATTR_LAST,
};
#define D_RAISE_NEW_BROADCAST_KEY_ATTR_MIN (__D_RAISE_NEW_BROADCAST_KEY_ATTR_FIRST + 1)
#define D_RAISE_NEW_BROADCAST_KEY_ATTR_MAX (__D_RAISE_NEW_BROADCAST_KEY_ATTR_LAST - 1)
typedef struct d_raise_new_broadcast_key_msg {
	uint32_t	ifindex;
} d_raise_new_broadcast_key_msg_t;
static struct nla_policy d_raise_new_broadcast_key_genl_policy[D_RAISE_NEW_BROADCAST_KEY_ATTR_MAX + 1] = {
	[D_RAISE_NEW_BROADCAST_KEY_ATTR_IFINDEX]							=	{ .type = NLA_U32	},
};

// D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST
enum {
	__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_TIMESTAMP,
	__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MIN (__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_LAST - 1)
typedef struct d_received_superman_discovery_request_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	int32_t			timestamp;
} d_received_superman_discovery_request_msg_t;
static struct nla_policy d_received_superman_discovery_request_genl_policy[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]						=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_TIMESTAMP]				=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST
enum {
	__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_TIMESTAMP,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MIN (__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_LAST - 1)
typedef struct d_received_superman_certificate_request_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	int32_t			timestamp;
} d_received_superman_certificate_request_msg_t;
static struct nla_policy d_received_superman_certificate_request_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_TIMESTAMP]			=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE
enum {
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_SK,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MIN (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_LAST - 1)
typedef struct d_received_superman_certificate_exchange_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		certificate_len;
	unsigned char*	certificate;
} d_received_superman_certificate_exchange_msg_t;
static struct nla_policy d_received_superman_certificate_exchange_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]				=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_SK]					=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]			=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY
enum {
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_SK,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MIN (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_LAST - 1)
typedef struct d_received_superman_certificate_exchange_with_broadcast_key_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		certificate_len;
	unsigned char*	certificate;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;
} d_received_superman_certificate_exchange_with_broadcast_key_msg_t;
static struct nla_policy d_received_superman_certificate_exchange_with_broadcast_key_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX]			=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]			=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_SK]				=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]		=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY]	=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE
enum {
	__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK,
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_TIMESTAMP,
	__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MIN (__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX (__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_LAST - 1)
typedef struct d_received_superman_authenticated_sk_response_msg {
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
} d_received_superman_certificate_authenticated_sk_response_msg_t;
static struct nla_policy d_received_superman_authenticated_sk_response_genl_policy[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_IFINDEX]		=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS]		=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK]				=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN	},
};

// D_RECEIVED_SUPERMAN_SK_INVALIDATE
enum {
	__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,
	__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MIN (__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX (__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_LAST - 1)
typedef struct d_received_superman_sk_invalidate_msg {
	uint32_t	ifindex;
	uint32_t	address;
} d_received_supermandsk_invalidate_msg_t;
static struct nla_policy d_received_superman_sk_invalidate_genl_policy[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX]					=	{ .type = NLA_U32	},
	[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]					=	{ .type = NLA_U32	},
};

// D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE
enum {
	__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_FIRST = 0,
	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX,
	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,
	__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_LAST,
};
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MIN (__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_FIRST + 1)
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX (__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_LAST - 1)
typedef struct d_received_superman_broadcast_key_exchange_msg {
	uint32_t		ifindex;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;
} d_received_superman_broadcast_key_exchange_msg_t;
static struct nla_policy d_received_superman_broadcast_key_exchange_genl_policy[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX]			=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]		=	{ .type = NLA_BINARY, SUPERMAN_BINARY_MAXLEN },
};


#ifdef __KERNEL__

static struct genl_family superman_genl_family = {
	.id				= 0, 	// GENL_ID_GENERATE = 0
	.hdrsize		= 0,
	.name			= K_SUPERMAN_FAMILY_NAME,
	.version		= 1,
	.maxattr		= K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX, //SUPERMAN_ATTR_MAX,
	.netnsok		= true,
	.parallel_ops	= false,
	.pre_doit		= NULL,
	.post_doit		= NULL/*,
	.mcast_bind		= NULL,
	.mcast_unbind	= NULL
*/
};

enum {
	K_SUPERMAN_MC_GROUP,
#define K_SUPERMAN_MC_GROUP K_SUPERMAN_MC_GROUP

	__K_SUPERMAN_MC_GROUP_MAX,
#define K_SUPERMAN_MC_GROUP_MAX __K_SUPERMAN_MC_GROUP_MAX
};

static const struct genl_multicast_group superman_mc_groups[] = {
	[K_SUPERMAN_MC_GROUP] = { .name	= K_SUPERMAN_MC_GROUP_NAME, },
};

#define GENL_PARSE(ATTR_MAX, POLICY)																							\
	/* Made this bigger to prevent a stack corruption. Still not sure why. */													\
	struct nlattr *attrs[ATTR_MAX + 2];																							\
	/* printk(KERN_INFO "SUPERMAN: Netlink - Received netlink (%s)...\n", superman_msg_type_to_str(info->genlhdr->cmd));*/		\
	/* printk(KERN_INFO "SUPERMAN: Netlink - \tParsing netlink message...\n"); */												\
	if(nlmsg_parse(info->nlhdr, superman_genl_family.hdrsize + GENL_HDRLEN, attrs, ATTR_MAX + 1, POLICY, NULL) < 0)				\
	{																															\
		printk(KERN_INFO "SUPERMAN: Netlink - \tFailed to parse netlink message\n");											\
		return 0;																												\
	}																															\
	/* printk(KERN_INFO "SUPERMAN: Netlink - \t...netlink message parsed ok.\n"); */

#define GENL_MALLOC(VAR, SIZE, ATTR) 			\
	SIZE = nla_len(attrs[ATTR]);				\
	if(SIZE > 0)								\
	{											\
		VAR = kmalloc(SIZE + 1, GFP_ATOMIC);	\
		VAR[SIZE] = '\0';						\
		nla_memcpy(VAR, attrs[ATTR], SIZE);		\
	}											\
	else										\
		VAR = NULL;

#define GENL_FREE(VAR)							\
	if(VAR != NULL)								\
		kfree(VAR);

int k_load_node_certificate_and_secure_interface(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		node_cert_filename_len;
	unsigned char*	node_cert_filename;
	uint32_t		node_privatekey_filename_len;
	unsigned char*	node_privatekey_filename;
	uint32_t		interface_name_len;
	unsigned char*	interface_name;

	GENL_PARSE(K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_MAX, k_load_node_certificate_and_secure_interface_genl_policy)
	GENL_MALLOC(node_cert_filename, node_cert_filename_len, K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME);
	GENL_MALLOC(node_privatekey_filename, node_privatekey_filename_len, K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME);
	GENL_MALLOC(interface_name, interface_name_len, K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_INTERFACE_NAME);

	LoadNodeCertificateAndSecureInterface(node_cert_filename_len, node_cert_filename, node_privatekey_filename_len, node_privatekey_filename, interface_name_len, interface_name);

	GENL_FREE(node_cert_filename);
	GENL_FREE(node_privatekey_filename);
	GENL_FREE(interface_name);

	return 0;
}

int k_secure_interface(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t	ifindex;

	GENL_PARSE(K_SECURE_INTERFACE_ATTR_MAX, k_secure_interface_genl_policy)
	ifindex = nla_get_u32(attrs[K_SECURE_INTERFACE_ATTR_IFINDEX]);

	SecureInterface(ifindex);

	return 0;
}

int k_secure_interface_by_name(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		interface_name_len;
	unsigned char*	interface_name;

	GENL_PARSE(K_SECURE_INTERFACE_BY_NAME_ATTR_MAX, k_secure_interface_by_name_genl_policy)
	GENL_MALLOC(interface_name, interface_name_len, K_SECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME);

	SecureInterfaceByName(interface_name_len, interface_name);

	GENL_FREE(interface_name);

	return 0;
}

int k_unsecure_interface(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t	ifindex;

	GENL_PARSE(K_UNSECURE_INTERFACE_ATTR_MAX, k_unsecure_interface_genl_policy)
	ifindex = nla_get_u32(attrs[K_UNSECURE_INTERFACE_ATTR_IFINDEX]);

	UnsecureInterface(ifindex);

	return 0;
}

int k_unsecure_interface_by_name(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		interface_name_len;
	unsigned char*	interface_name;

	GENL_PARSE(K_UNSECURE_INTERFACE_BY_NAME_ATTR_MAX, k_unsecure_interface_by_name_genl_policy)
	GENL_MALLOC(interface_name, interface_name_len, K_UNSECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME);

	UnsecureInterfaceByName(interface_name_len, interface_name);

	GENL_FREE(interface_name);

	return 0;
}

// int k_update_superman_interface_table_entry(struct sk_buff *skb_msg, struct genl_info *info)
// {
// 	uint32_t	interface_name_len;
// 	unsigned char*	interface_name;
// 	bool		monitor_flag;

// 	GENL_PARSE(K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MAX, k_update_superman_interface_table_entry_genl_policy)
// 	GENL_MALLOC(interface_name, interface_name_len, K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_INTERFACE_NAME);
// 	monitor_flag = nla_get_flag(attrs[K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MONITOR_FLAG]);

// 	UpdateSupermanInterfaceTableEntry(interface_name_len, interface_name, monitor_flag);

// 	GENL_FREE(interface_name);

// 	return 0;
// }

int k_unload_all(struct sk_buff *skb_msg, struct genl_info *info)
{
	GENL_PARSE(K_UNLOAD_ALL_ATTR_MAX, k_unload_all_genl_policy)

	UnloadAll();

	return 0;
}

int k_update_superman_security_table_entry(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t		address;
	uint8_t			flag;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		ske_len;
	unsigned char*	ske;
	uint32_t		skp_len;
	unsigned char*	skp;
	int32_t			timestamp;
	GENL_PARSE(K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX, k_update_superman_security_table_entry_genl_policy)
	ifindex = nla_get_u32(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS]);
	flag = nla_get_u8(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG]);
	GENL_MALLOC(sk, sk_len, K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK);
	GENL_MALLOC(ske, ske_len, K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE);
	GENL_MALLOC(skp, skp_len, K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP);
	nla_memcpy(&timestamp, attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_TIMESTAMP], sizeof(int32_t));

	UpdateSupermanSecurityTableEntry(ifindex, address, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);

	GENL_FREE(sk);
	GENL_FREE(ske);
	GENL_FREE(skp);

	return 0;
}

int k_update_superman_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		ske_len;
	unsigned char*	ske;
	uint32_t		skp_len;
	unsigned char*	skp;
	bool			overwrite;

	GENL_PARSE(K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX, k_update_superman_broadcast_key_genl_policy)

	// printk(KERN_INFO "k_update_superman_broadcast_key...\n");
	ifindex = nla_get_u32(attrs[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_IFINDEX]);
	GENL_MALLOC(sk, sk_len, K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SK);
	GENL_MALLOC(ske, ske_len, K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKE);
	GENL_MALLOC(skp, skp_len, K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKP);
	overwrite = nla_get_flag(attrs[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_OVERWRITE]);

	// printk(KERN_INFO "sk_len: %d\n", sk_len);
	// printk(KERN_INFO "ske_len: %d\n", ske_len);
	// printk(KERN_INFO "skp_len: %d\n", skp_len);
	// printk(KERN_INFO "overwrite: %d\n", overwrite);

	UpdateSupermanBroadcastKey(ifindex, sk_len, sk, ske_len, ske, skp_len, skp, overwrite);

	//printk(KERN_INFO "...k_update_superman_broadcast_key - complete.\n");

	GENL_FREE(sk);
	GENL_FREE(ske);
	GENL_FREE(skp);

	return 0;
}

int k_trigger_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	//printk(KERN_INFO "SUPERMAN: Netlink - Calling TriggerDiscoveryRequest...\n");
	TriggerSupermanDiscoveryRequest();

	//printk(KERN_INFO "SUPERMAN: Netlink - Done.\n");
	return 0;
}

int k_send_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t 		sk_len;
	unsigned char* 	sk;
	GENL_PARSE(K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX, k_send_superman_discovery_request_genl_policy)

	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]);

	//printk(KERN_INFO "SUPERMAN: Netlink - Reading SK length...\n");
	GENL_MALLOC(sk, sk_len, K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK);

	//printk(KERN_INFO "SUPERMAN: Netlink - Calling SendDiscoveryRequest...\n");
	SendSupermanDiscoveryRequest(ifindex, sk_len, sk);

	//printk(KERN_INFO "SUPERMAN: Netlink - Freeing SK memory...\n");
	GENL_FREE(sk);

	//printk(KERN_INFO "SUPERMAN: Netlink - Done.\n");
	return 0;
}

int k_send_superman_certificate_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t 		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX, k_send_superman_certificate_request_genl_policy)
	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK);

	// printk(KERN_INFO "SUPERMAN: Netlink - k_send_superman_certificate_request...\n");

	SendSupermanCertificateRequest(ifindex, address, sk_len, sk);

	GENL_FREE(sk);

	// printk(KERN_INFO "SUPERMAN: Netlink - ... k_send_superman_certificate_request done.\n");

	return 0;
}

int k_send_superman_certificate_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		certificate_len;
	unsigned char*	certificate;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX, k_send_superman_certificate_exchange_genl_policy)
	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]);
	GENL_MALLOC(certificate, certificate_len, K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE);

	SendSupermanCertificateExchange(ifindex, address, certificate_len, certificate);

	GENL_FREE(certificate);

	return 0;
}

int k_send_superman_certificate_exchange_with_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		certificate_len;
	unsigned char*	certificate;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX, k_send_superman_certificate_exchange_with_broadcast_key_genl_policy)
	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]);
	GENL_MALLOC(certificate, certificate_len, K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE);

	SendSupermanCertificateExchangeWithBroadcastKey(ifindex, address, certificate_len, certificate);

	GENL_FREE(certificate);

	return 0;
}

int k_send_superman_broadcast_key_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t		ifindex;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;
	bool			only_if_changed;
	GENL_PARSE(K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX, k_send_superman_broadcast_key_exchange_genl_policy)
	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX]);
	GENL_MALLOC(broadcast_key, broadcast_key_len, K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY);
	only_if_changed = nla_get_flag(attrs[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_ONLY_IF_CHANGED]);

	SendSupermanBroadcastKeyExchange(ifindex, broadcast_key_len, broadcast_key, only_if_changed);

	GENL_FREE(broadcast_key);

	return 0;
}

int k_send_superman_sk_invalidate(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t	ifindex;
	uint32_t	address;
	GENL_PARSE(K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX, k_send_superman_sk_invalidate_genl_policy)
	ifindex = nla_get_u32(attrs[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]);

	SendSupermanSKInvalidate(ifindex, address);

	return 0;
}

int d_load_node_certificate_then_secure_interface(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_raise_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_raise_new_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_certificate_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_certificate_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_certificate_exchange_with_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_authenticated_sk_response(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_sk_invalidate(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

int d_received_superman_broadcast_key_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	return 0;
}

#else

bool is_service = false;

#define GENL_PARSE(ATTR_MAX, POLICY)																						\
	struct nlattr *attrs[ATTR_MAX + 1];																						\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Received netlink (%s)...\n", superman_msg_type_to_str(genlmsg_hdr(nlh)->cmd));		\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: \tParsing generic netlink message...\n");											\
	if(genlmsg_parse(nlh, 0, attrs, ATTR_MAX, POLICY) < 0)																	\
	{																														\
		lprintf(LOG_LEVEL_ERROR, "Netlink: \tFailed to parse netlink message\n");											\
		return NL_SKIP;																										\
	}

#define GENL_MALLOC(VAR, SIZE, ATTR) 																						\
	SIZE = nla_len(attrs[ATTR]);																							\
	if(SIZE > 0)																											\
	{																														\
		VAR = malloc(SIZE + 1);																								\
		nla_memcpy(VAR, attrs[ATTR], SIZE);																					\
		if(VAR[SIZE] != '\0')																								\
			VAR[SIZE] = '\0';																								\
	}																														\
	else																													\
		VAR = NULL;

#define GENL_FREE(VAR)																										\
	if(VAR != NULL)																											\
		free(VAR);


int d_load_node_certificate_then_secure_interface(struct nlmsghdr *nlh)
{
	uint32_t		ifindex;
	uint32_t		node_cert_filename_len;
	unsigned char*	node_cert_filename;
	uint32_t		node_privatekey_filename_len;
	unsigned char*	node_privatekey_filename;

	lprintf(LOG_LEVEL_DEBUG, "Netlink: d_load_node_certificate_then_secure_interface - parsing arguments.\n");

	GENL_PARSE(D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_MAX, d_load_node_certificate_then_secure_interface_genl_policy)
	ifindex = nla_get_u32(attrs[D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_IFINDEX]);
	GENL_MALLOC(node_cert_filename, node_cert_filename_len, D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME);
	GENL_MALLOC(node_privatekey_filename, node_privatekey_filename_len, D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME);

	lprintf(LOG_LEVEL_DEBUG, "Netlink: d_load_node_certificate_then_secure_interface - invoking LoadNodeCertificateThenSecureInterface.\n");

	LoadNodeCertificateThenSecureInterface(ifindex, node_cert_filename_len, node_cert_filename, node_privatekey_filename_len, node_privatekey_filename);

	lprintf(LOG_LEVEL_DEBUG, "Netlink: d_load_node_certificate_then_secure_interface - freeing arguments\n");

	GENL_FREE(node_cert_filename);
	GENL_FREE(node_privatekey_filename);

	lprintf(LOG_LEVEL_DEBUG, "Netlink: d_load_node_certificate_then_secure_interface - returning NL_OK.\n");

	return NL_OK;
}

int d_raise_superman_discovery_request(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX, d_raise_superman_discovery_request_genl_policy)

	int32_t		ifindex;
	ifindex = nla_get_u32(attrs[D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]);

	RaiseSupermanDiscoveryRequest(ifindex);

	return NL_OK;
}

int d_raise_new_broadcast_key(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RAISE_NEW_BROADCAST_KEY_ATTR_MAX, d_raise_new_broadcast_key_genl_policy)

	int32_t		ifindex;
	ifindex = nla_get_u32(attrs[D_RAISE_NEW_BROADCAST_KEY_ATTR_IFINDEX]);
	
	RaiseNewBroadcastKey(ifindex);

	return NL_OK;
}

int d_received_superman_discovery_request(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX, d_received_superman_discovery_request_genl_policy)

	int32_t			ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	int32_t			timestamp;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK);
	nla_memcpy(&timestamp, attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_TIMESTAMP], sizeof(int32_t));

	ReceivedSupermanDiscoveryRequest(ifindex, address, sk_len, sk, timestamp);

	GENL_FREE(sk);

	return NL_OK;
}

int d_received_superman_certificate_request(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX, d_received_superman_certificate_request_genl_policy)

	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	int32_t			timestamp;

	ifindex =  nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK);
	nla_memcpy(&timestamp, attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_TIMESTAMP], sizeof(int32_t));

	ReceivedSupermanCertificateRequest(ifindex, address, sk_len, sk, timestamp);

	GENL_FREE(sk);

	return NL_OK;
}

int d_received_superman_certificate_exchange(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX, d_received_superman_certificate_exchange_genl_policy)

	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		certificate_len;
	unsigned char*	certificate;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_SK);
	GENL_MALLOC(certificate, certificate_len, D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE);

	ReceivedSupermanCertificateExchange(ifindex, address, sk_len, sk, certificate_len, certificate);

	GENL_FREE(sk);
	GENL_FREE(certificate);

	return NL_OK;
}

int d_received_superman_certificate_exchange_with_broadcast_key(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX, d_received_superman_certificate_exchange_with_broadcast_key_genl_policy)

	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		certificate_len;
	unsigned char*	certificate;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_SK);
	GENL_MALLOC(certificate, certificate_len, D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE);
	GENL_MALLOC(broadcast_key, broadcast_key_len, D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY);

	ReceivedSupermanCertificateExchangeWithBroadcastKey(ifindex, address, sk_len, sk, certificate_len, certificate, broadcast_key_len, broadcast_key);

	GENL_FREE(sk);
	GENL_FREE(certificate);
	GENL_FREE(broadcast_key);

	return NL_OK;
}

int d_received_superman_authenticated_sk_response(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX, d_received_superman_authenticated_sk_response_genl_policy)

	uint32_t		ifindex;
	uint32_t		address;
	uint32_t		sk_len;
	unsigned char*	sk;
	uint32_t		timestamp;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS]);
	GENL_MALLOC(sk, sk_len, D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK);
	nla_memcpy(&timestamp, attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_TIMESTAMP], sizeof(int32_t));

	ReceivedSupermanAuthenticatedSKResponse(ifindex, address, sk_len, sk, timestamp);

	GENL_FREE(sk);

	return NL_OK;
}

int d_received_superman_sk_invalidate(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX, d_received_superman_sk_invalidate_genl_policy)

	uint32_t	ifindex;
	uint32_t	address;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX]);
	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]);

	ReceivedSupermanSKInvalidate(ifindex, address);

	return NL_OK;
}

int d_received_superman_broadcast_key_exchange(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX, d_received_superman_broadcast_key_exchange_genl_policy)

	uint32_t 		ifindex;
	uint32_t		broadcast_key_len;
	unsigned char*	broadcast_key;

	ifindex = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX]);
	GENL_MALLOC(broadcast_key, broadcast_key_len, D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY);

	ReceivedSupermanBroadcastKeyExchange(ifindex, broadcast_key_len, broadcast_key);

	GENL_FREE(broadcast_key);

	return NL_OK;
}

bool hadMessages = false;

int d_superman_messaging_callback(struct nl_msg* msg, void* arg)
{
	if(!is_service)
		return NL_SKIP;

	hadMessages = true;

	struct nlmsghdr *nlh = NULL;
	struct genlmsghdr* genlh = NULL;

	nlh = nlmsg_hdr(msg);
	if(!nlh)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: Failed to get the Netlink message header\n");
		return NL_SKIP;
	}

	genlh = genlmsg_hdr(nlh);
	if(!genlh)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: Failed to get the Generic Netlink message header\n");
		return NL_SKIP;
	}

	int result;
	switch(genlh->cmd)
	{
		case D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE:
			lprintf(LOG_LEVEL_DEBUG, "Netlink: Calling d_load_node_certificate_then_secure_interface...\n");
			result = d_load_node_certificate_then_secure_interface(nlh);
			lprintf(LOG_LEVEL_DEBUG, "Netlink: Finished d_load_node_certificate_then_secure_interface.\n");
			break;
		case D_RAISE_SUPERMAN_DISCOVERY_REQUEST:
			result = d_raise_superman_discovery_request(nlh);
			break;
		case D_RAISE_NEW_BROADCAST_KEY:
			result = d_raise_new_broadcast_key(nlh);
			break;
		case D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST:
			result = d_received_superman_discovery_request(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST:
			result = d_received_superman_certificate_request(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE:
			result = d_received_superman_certificate_exchange(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY:
			result = d_received_superman_certificate_exchange_with_broadcast_key(nlh);
			break;
		case D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE:
			result = d_received_superman_authenticated_sk_response(nlh);
			break;
		case D_RECEIVED_SUPERMAN_SK_INVALIDATE:
			result = d_received_superman_sk_invalidate(nlh);
			break;
		case D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE:
			result = d_received_superman_broadcast_key_exchange(nlh);
			break;
		default:
			lprintf(LOG_LEVEL_WARNING, "SUPERMAN: Unhandled message type %d, (%s).\n", genlh->cmd, superman_msg_type_to_str(genlh->cmd));
			result = NL_SKIP;
			break;
	}

	lprintf(LOG_LEVEL_DEBUG, "Netlink: Finished process \"%s\", result: %d.\n", superman_msg_type_to_str(genlh->cmd), result);
	return result;
}

bool CheckForMessages(void)
{
	if(nlsk)
	{
		int rc = 0;

		// Receive messages
		hadMessages = false;
		rc = nl_recvmsgs_default(nlsk);
		if(rc != -NLE_AGAIN && rc < 0)
		{
			lprintf(LOG_LEVEL_ERROR, "Netlink: nl_recvmsgs_default failed, rc %d\n", rc);
			DeInitNetlink();
		}
		return hadMessages;
	}
}

#endif

#ifdef __KERNEL__


#define SUPERMAN_OP(CMD, POLICY, DOIT)		\
	{										\
		.cmd		= CMD,					\
		.flags		= 0,					\
		.policy		= POLICY,				\
		.doit		= DOIT,					\
		.dumpit		= NULL,					\
		.done		= NULL,					\
	},

static struct genl_ops superman_ops[SUPERMAN_MAX] = {

	// Daemon to Kernel functions
	SUPERMAN_OP(K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE, k_load_node_certificate_and_secure_interface_genl_policy, k_load_node_certificate_and_secure_interface)
	SUPERMAN_OP(K_SECURE_INTERFACE, k_secure_interface_genl_policy, k_secure_interface)
	SUPERMAN_OP(K_SECURE_INTERFACE_BY_NAME, k_secure_interface_by_name_genl_policy, k_secure_interface_by_name)
	SUPERMAN_OP(K_UNSECURE_INTERFACE, k_unsecure_interface_genl_policy, k_unsecure_interface)
	SUPERMAN_OP(K_UNSECURE_INTERFACE_BY_NAME, k_unsecure_interface_by_name_genl_policy, k_unsecure_interface_by_name)
	// SUPERMAN_OP(K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY, k_update_superman_interface_table_entry_genl_policy, k_update_superman_interface_table_entry)
	SUPERMAN_OP(K_UNLOAD_ALL, k_unload_all_genl_policy, k_unload_all)
	SUPERMAN_OP(K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY, k_update_superman_security_table_entry_genl_policy, k_update_superman_security_table_entry)
	SUPERMAN_OP(K_UPDATE_SUPERMAN_BROADCAST_KEY, k_update_superman_broadcast_key_genl_policy, k_update_superman_broadcast_key)
	SUPERMAN_OP(K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST, k_trigger_superman_discovery_request_genl_policy, k_trigger_superman_discovery_request)
	SUPERMAN_OP(K_SEND_SUPERMAN_DISCOVERY_REQUEST, k_send_superman_discovery_request_genl_policy, k_send_superman_discovery_request)
	SUPERMAN_OP(K_SEND_SUPERMAN_CERTIFICATE_REQUEST, k_send_superman_certificate_request_genl_policy, k_send_superman_certificate_request)
	SUPERMAN_OP(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE, k_send_superman_certificate_exchange_genl_policy, k_send_superman_certificate_exchange)
	SUPERMAN_OP(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY, k_send_superman_certificate_exchange_with_broadcast_key_genl_policy, k_send_superman_certificate_exchange_with_broadcast_key)
	SUPERMAN_OP(K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE, k_send_superman_broadcast_key_exchange_genl_policy, k_send_superman_broadcast_key_exchange)
	SUPERMAN_OP(K_SEND_SUPERMAN_SK_INVALIDATE, k_send_superman_sk_invalidate_genl_policy, k_send_superman_sk_invalidate)

	// Kernel to Daemon functions
	SUPERMAN_OP(D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE, d_load_node_certificate_then_secure_interface_genl_policy, d_load_node_certificate_then_secure_interface)
	SUPERMAN_OP(D_RAISE_SUPERMAN_DISCOVERY_REQUEST, d_raise_superman_discovery_request_genl_policy, d_raise_superman_discovery_request)
	SUPERMAN_OP(D_RAISE_NEW_BROADCAST_KEY, d_raise_new_broadcast_key_genl_policy, d_raise_new_broadcast_key)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST, d_received_superman_discovery_request_genl_policy, d_received_superman_discovery_request)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST, d_received_superman_certificate_request_genl_policy, d_received_superman_certificate_request)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE, d_received_superman_certificate_exchange_genl_policy,  d_received_superman_certificate_exchange)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY, d_received_superman_certificate_exchange_with_broadcast_key_genl_policy, d_received_superman_certificate_exchange_with_broadcast_key)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE, d_received_superman_authenticated_sk_response_genl_policy, d_received_superman_authenticated_sk_response)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_SK_INVALIDATE, d_received_superman_sk_invalidate_genl_policy, d_received_superman_sk_invalidate)
	SUPERMAN_OP(D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE, d_received_superman_broadcast_key_exchange_genl_policy, d_received_superman_broadcast_key_exchange)
};

#endif // __KERNEL__

#ifndef __KERNEL__

#define D_GENL_START(K_SUPERMAN_OPERATION)																				\
	struct nl_msg *msg;																									\
	int fail = 0;																										\
																														\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Starting netlink (%s)...\n", superman_msg_type_to_str(K_SUPERMAN_OPERATION));	\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Constructing the netlink message...\n");											\
																														\
	/* Construct a new message */																						\
	msg = nlmsg_alloc();																								\
																														\
	/* Add the Generic Netlink header to the netlink message. */														\
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, superman_family_id, 0, 0, K_SUPERMAN_OPERATION, 0);						\
																														\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Adding the attributes to the message...\n");

#define D_GENL_FINISH																									\
	if(fail == 0) {																										\
		lprintf(LOG_LEVEL_DEBUG, "Netlink: Sending the netlink message...\n");											\
		/* Send the message over the netlink socket */																	\
		int ret = nl_send_auto(nlsk, msg);																				\
		if(ret < 0) { 																									\
			lprintf(LOG_LEVEL_ERROR, "Netlink: Failed to send the message.\n");											\
		} else { 																										\
			lprintf(LOG_LEVEL_DEBUG, "Netlink: Sent a message of %d bytes.\n", ret);									\
		}																												\
	}																													\
	else {																												\
		lprintf(LOG_LEVEL_ERROR, "Netlink: Failed to add the attributes to the message.\n");							\
	}																													\
																														\
	/* Cleanup */																										\
	nlmsg_free(msg);																									\
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Finished netlink send.\n");

#define D_GENL_CALC_NLA_SIZE(contents) nlmsg_alloc()

void LoadNodeCertificateAndSecureInterface(uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename, uint32_t interface_name_len, unsigned char* interface_name)
{
	D_GENL_START(K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE)
	if(
		nla_put		(msg,	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME,		node_cert_filename_len,				node_cert_filename			) ||
		nla_put		(msg,	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME,		node_privatekey_filename_len,		node_privatekey_filename	) ||
		nla_put		(msg,	K_LOAD_NODE_CERTIFICATE_AND_SECURE_INTERFACE_ATTR_INTERFACE_NAME,			interface_name_len,					interface_name				))
		fail = 1;
	D_GENL_FINISH
}

void SecureInterface(uint32_t ifindex)
{
	D_GENL_START(K_SECURE_INTERFACE)
	if(
		nla_put_u32	(msg,	K_SECURE_INTERFACE_ATTR_IFINDEX,																	ifindex		))
		fail = 1;
	D_GENL_FINISH
}

void SecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	D_GENL_START(K_SECURE_INTERFACE_BY_NAME)
	if(
		nla_put		(msg,	K_SECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME,								interface_name_len,	interface_name	))
		fail = 1;
	D_GENL_FINISH
}

void UnsecureInterface(uint32_t ifindex)
{
	D_GENL_START(K_UNSECURE_INTERFACE)
	if(
		nla_put_u32	(msg,	K_UNSECURE_INTERFACE_ATTR_IFINDEX,																	ifindex		))
		fail = 1;
	D_GENL_FINISH
}

void UnsecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	D_GENL_START(K_UNSECURE_INTERFACE_BY_NAME)
	if(
		nla_put		(msg,	K_UNSECURE_INTERFACE_BY_NAME_ATTR_INTERFACE_NAME,							interface_name_len,	interface_name	))
		fail = 1;
	D_GENL_FINISH
}

// void UpdateSupermanInterfaceTableEntry(uint32_t interface_name_len, unsigned char* interface_name, bool monitor_flag)
// {
// 	D_GENL_START(K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY)
// 	if(	nla_put		(msg,	K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_INTERFACE_NAME,				interface_name_len,	interface_name	))
// 		fail = 1;
// 	if( monitor_flag &&
// 		nla_put_flag(msg,	K_UPDATE_SUPERMAN_INTERFACE_TABLE_ENTRY_ATTR_MONITOR_FLAG														))
// 		fail = 1;
// 	D_GENL_FINISH
// }

void UnloadAll()
{
	D_GENL_START(K_UNLOAD_ALL)
	D_GENL_FINISH
}

void UpdateSupermanSecurityTableEntry(uint32_t ifindex, uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	D_GENL_START(K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY)
	if(
		nla_put_u32	(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_IFINDEX,												ifindex		) ||
		nla_put_u32	(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS,												address		) ||
		nla_put_u8	(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG,													flag		) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK,								sk_len,					sk			) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE,							ske_len,				ske			) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP,							skp_len,				skp			) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_TIMESTAMP,						sizeof(int32_t),		&timestamp	) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_IFINDEX,						sizeof(int32_t),		&ifindex	))
		fail = 1;
	D_GENL_FINISH
}

void UpdateSupermanBroadcastKey(uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	D_GENL_START(K_UPDATE_SUPERMAN_BROADCAST_KEY)
	if(
		nla_put_u32	(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_IFINDEX,														ifindex		) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SK,									sk_len,					sk			) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKE,									ske_len,				ske			) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_SKP,									skp_len,				skp			))
		fail = 1;
	if( overwrite &&
		nla_put_flag(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_OVERWRITE																	))
		fail = 1;
	D_GENL_FINISH
}

void TriggerSupermanDiscoveryRequest()
{
	D_GENL_START(K_TRIGGER_SUPERMAN_DISCOVERY_REQUEST)
	D_GENL_FINISH
}

void SendSupermanDiscoveryRequest(uint32_t ifindex, uint32_t sk_len, unsigned char* sk)
{
	D_GENL_START(K_SEND_SUPERMAN_DISCOVERY_REQUEST)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,														ifindex		) ||
		nla_put		(msg,	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,										sk_len,				sk			))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_REQUEST)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX,													ifindex		) ||
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,													address		) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,									sk_len,				sk			))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX,													ifindex			) ||
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,													address			) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,							certificate_len,	certificate		))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX,								ifindex			) ||
		nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,								address			) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,		certificate_len,	certificate		))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key, bool only_if_changed)
{
	D_GENL_START(K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX,												ifindex			) ||
		nla_put		(msg,	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,						broadcast_key_len, 	broadcast_key	))
		fail = 1;
	if( only_if_changed &&
		nla_put_flag	(msg,	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_ONLY_IF_CHANGED ))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanSKInvalidate(uint32_t ifindex, uint32_t address)
{
	D_GENL_START(K_SEND_SUPERMAN_SK_INVALIDATE)
	if(
		nla_put_u32	(msg,	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX,															ifindex			) ||
		nla_put_u32	(msg,	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,															address			))
		fail = 1;
	D_GENL_FINISH
}

#else

#define K_GENL_START(D_SUPERMAN_OPERATION)																						\
	struct sk_buff* skb;																										\
	void* msg;																													\
	int fail = 0;																												\
																																\
	/* printk(KERN_INFO "SUPERMAN: Netlink - Starting netlink (%s)...\n", superman_msg_type_to_str(D_SUPERMAN_OPERATION));*/	\
	/* printk(KERN_INFO "SUPERMAN: Netlink - \tConstructing netlink message of %lu bytes...\n", NLMSG_GOODSIZE); */				\
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);																				\
	if(!skb) {																													\
		printk(KERN_INFO "SUPERMAN: Netlink - \tNetlink message construction failure.\n");										\
		return;																													\
	}																															\
																																\
	/* printk(KERN_INFO "SUPERMAN: Netlink - Adding generic netlink header...\n"); */											\
	msg = genlmsg_put( skb,																										\
	                   0,           			/* PID is whatever */															\
	                   0,           			/* Sequence number (don't care) */												\
	                   &superman_genl_family,   /* Pointer to family struct */													\
	                   0,                     	/* Flags */																		\
	                   D_SUPERMAN_OPERATION 	/* Generic netlink command */													\
	                   );																										\
	if(!msg)																													\
	{																															\
		printk(KERN_INFO "SUPERMAN: Netlink - \tGeneric Netlink message construction failure.\n");								\
		return;																													\
	}																															\
	/* printk(KERN_INFO "SUPERMAN: Netlink - Adding attributes to the message...\n"); */

#define K_GENL_FINISH																											\
	if(fail == 1)																												\
	{																															\
		printk(KERN_INFO "SUPERMAN: Netlink - \tAdding attributes failed.\n");													\
		genlmsg_cancel(skb, msg);																								\
		nlmsg_free(skb);																										\
	} else {																													\
		/* Finalise the message */																								\
		genlmsg_end(skb, msg);																									\
																																\
		/* printk(KERN_INFO "SUPERMAN: Netlink - \tMulticasting netlink message...\n"); */										\
																																\
		fail = genlmsg_multicast(&superman_genl_family, skb, 0, K_SUPERMAN_MC_GROUP, GFP_ATOMIC);								\
																																\
		/*	If error - fail.																									\
			ESRCH is "forever alone" case - no one is listening for our messages												\
			and it's ok, since userspace daemon can be unloaded.																\
		*/																														\
		if(fail && fail != -ESRCH)																								\
		{																														\
			printk(KERN_INFO "SUPERMAN: Netlink - \tFailed to send message. fail = %d\n", fail);								\
			genlmsg_cancel(skb, msg);																							\
		}																														\
	}																															\
	/* printk(KERN_INFO "SUPERMAN: Netlink - Finised netlink.\n"); */

void LoadNodeCertificateThenSecureInterface(uint32_t ifindex, uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename)
{
	K_GENL_START(D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE)
	if(
		nla_put_u32	(skb,	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_IFINDEX,														ifindex						) ||
		nla_put		(skb,	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_NODE_CERT_FILENAME,		node_cert_filename_len,				node_cert_filename			) ||
		nla_put		(skb,	D_LOAD_NODE_CERTIFICATE_THEN_SECURE_INTERFACE_ATTR_PRIVATEKEY_FILENAME,	node_privatekey_filename_len,	node_privatekey_filename	))
		fail = 1;
	K_GENL_FINISH
}

void RaiseSupermanDiscoveryRequest(uint32_t ifindex)
{
	K_GENL_START(D_RAISE_SUPERMAN_DISCOVERY_REQUEST)
	if(
		nla_put_u32	(skb,	D_RAISE_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,													ifindex			))
		fail = 1;
	K_GENL_FINISH
}

void RaiseNewBroadcastKey(uint32_t ifindex)
{
	K_GENL_START(D_RAISE_NEW_BROADCAST_KEY)
	if(
		nla_put_u32	(skb,	D_RAISE_NEW_BROADCAST_KEY_ATTR_IFINDEX,																ifindex			))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanDiscoveryRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST)
	if(
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_IFINDEX,													ifindex			) ||
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS,													address			) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,									sk_len,				sk				) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_TIMESTAMP,							sizeof(int32_t),	&timestamp		)
		)
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST)
	if(
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_IFINDEX,												ifindex			) ||
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,												address			) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,								sk_len,				sk				) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_TIMESTAMP,							sizeof(int32_t),	&timestamp		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	struct security_table_entry* e = NULL;
	if(GetSecurityTableEntry(ifindex, address, &e))
	{
		K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE)
		if(
			nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_IFINDEX,												ifindex		) ||
			nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,												address		) ||
			nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_SK,								e->sk_len,			e->sk		) ||
			nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,						certificate_len,	certificate	))
			fail = 1;
		K_GENL_FINISH
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	struct security_table_entry* e = NULL;
	if(GetSecurityTableEntry(ifindex, address, &e))
	{
		K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY)
		if(
			nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_IFINDEX,							ifindex			) ||
			nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,							address			) ||
			nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_SK,			e->sk_len,			e->sk			) ||
			nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,	certificate_len,	certificate		) ||
			nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY,	broadcast_key_len,	broadcast_key	))
			fail = 1;
		K_GENL_FINISH
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE)
	if(
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_IFINDEX,												ifindex			) ||
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS,												address			) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK,								sk_len,				sk				) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_TIMESTAMP,						sizeof(int32_t),	&timestamp		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanSKInvalidate(uint32_t ifindex, uint32_t address)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_SK_INVALIDATE)
	if(
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_IFINDEX,															ifindex			) ||
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,															address			))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE)
	if(
		nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_IFINDEX,												ifindex			) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,						broadcast_key_len,	broadcast_key	))
		fail = 1;
	K_GENL_FINISH
}

#endif

#ifdef __KERNEL__
bool InitNetlink(void)
#else
bool InitNetlink(bool service)	
#endif
{
#ifdef __KERNEL__
	superman_genl_family.ops		= superman_ops;
	superman_genl_family.n_ops		= ARRAY_SIZE(superman_ops);
	superman_genl_family.mcgrps		= superman_mc_groups;
	superman_genl_family.n_mcgrps	= ARRAY_SIZE(superman_mc_groups);
	genl_register_family(&superman_genl_family);
#else
	is_service = service;
	int rc = 0;

	// Allocate a new socket
	nlsk = nl_socket_alloc();
	if(!nlsk) {
		lprintf(LOG_LEVEL_ERROR, "Netlink: nl_socket_alloc failed\n");
		return false;
	}

	// Disable sequence number checking
	nl_socket_disable_seq_check(nlsk);

	// Entry callback for valid incoming messages
	rc = nl_socket_modify_cb(nlsk, NL_CB_VALID, NL_CB_CUSTOM, d_superman_messaging_callback, NULL);
	if(rc < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: nl_cb_set failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// Connect to Generic Netlink bus
	rc = genl_connect(nlsk);
	if(rc < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: genl_connect failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// We're after a non-blocking socket so we can do other things in our own time.
	rc = nl_socket_set_nonblocking(nlsk);
	if(rc < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: nl_socket_set_nonblocking failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// Allocate libnl generic netlink cache
	rc = genl_ctrl_alloc_cache(nlsk, &genl_cache);
	if(rc < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: genl_ctrl_alloc_cache failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// Find the SUPERMAN family identifier.
	superman_family_id = genl_ctrl_resolve(nlsk, K_SUPERMAN_FAMILY_NAME);
	if(superman_family_id < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: No SUPERMAN netlink family found. Is the SUPERMAN kernel module loaded?\n");
		DeInitNetlink();
		return false;
	}


	// Resolve keymon muilticast group
	superman_mc_group_id = genl_ctrl_resolve_grp(nlsk, K_SUPERMAN_FAMILY_NAME, K_SUPERMAN_MC_GROUP_NAME);
	if(superman_mc_group_id < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: Unabled to resolve the netlink group. Check to see if the kernel module is running, rc %d\n", superman_mc_group_id);
		DeInitNetlink();
		return false;
	}

	// Join keymon multicast group
	rc = nl_socket_add_memberships(nlsk, superman_mc_group_id, 0);
	if (rc < 0)
	{
		lprintf(LOG_LEVEL_ERROR, "Netlink: nl_socket_add_membership failed, rc %d\n", rc);
		superman_mc_group_id = -1;
		DeInitNetlink();
		return false;
	}

#endif

	netlink_loaded = true;
	return true;
}

void DeInitNetlink(void)
{
#ifdef __KERNEL__
	genl_unregister_family(&superman_genl_family);
#else
	lprintf(LOG_LEVEL_DEBUG, "Netlink: Unloading...\n");
	superman_mc_group_id = -1;

	if(genl_cache)
	{
		nl_cache_free(genl_cache);
		genl_cache = NULL;
	}

	if(nlsk)
	{
		nl_socket_free(nlsk);
		nlsk = NULL;
	}
#endif

	netlink_loaded = false;
}
