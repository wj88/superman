#include "netlink.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>

#include "packet.h"
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

#endif

#define K_SUPERMAN_FAMILY_NAME		"K_SUPERMAN"
#define K_SUPERMAN_MC_GROUP_NAME	"K_SUPERMAN_GROUP"

enum {
// Local Kernel state updating from the Daemon
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY,
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY

	K_UPDATE_SUPERMAN_BROADCAST_KEY,
#define K_UPDATE_SUPERMAN_BROADCAST_KEY K_UPDATE_SUPERMAN_BROADCAST_KEY

// Daemon instructing Kernel to send packets
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


#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_NAME				"Update a security table entry"
#define K_UPDATE_SUPERMAN_BROADCAST_KEY_NAME					"Update the broadcast Key"

#define K_SEND_SUPERMAN_DISCOVERY_REQUEST_NAME					"Send a discovery request"
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST_NAME				"Send a certificate request"
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_NAME				"Send a certificate exchange"
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME		"Send a certificate exchange (inc. broadcast key)"
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME				"Send a broadcast key exchange"
#define K_SEND_SUPERMAN_SK_INVALIDATE_NAME					"Send an SK invalidate"

#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_NAME				"Received a discovery request"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_NAME				"Received a certificate request"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_NAME				"Received a certificate exchange"
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME	"Received a certificate exchange (inc. broadcast key)"
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME			"Received an authenticated SK response"
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE_NAME					"Received an SK invalidate"
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME				"Received a broadcast key exchange"

static struct {
	int type;
	char *name;
} superman_typenames[SUPERMAN_MAX] = {
	{ K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY,			K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_NAME				},
	{ K_UPDATE_SUPERMAN_BROADCAST_KEY,				K_UPDATE_SUPERMAN_BROADCAST_KEY_NAME					},
	{ K_SEND_SUPERMAN_DISCOVERY_REQUEST,				K_SEND_SUPERMAN_DISCOVERY_REQUEST_NAME					},
	{ K_SEND_SUPERMAN_CERTIFICATE_REQUEST,				K_SEND_SUPERMAN_CERTIFICATE_REQUEST_NAME				},
	{ K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE,				K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_NAME				},
	{ K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME		},
	{ K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE,			K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME				},
	{ K_SEND_SUPERMAN_SK_INVALIDATE,				K_SEND_SUPERMAN_SK_INVALIDATE_NAME					},
	{ D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST,			D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_NAME				},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST,			D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_NAME				},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE,			D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_NAME				},
	{ D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_NAME	},
	{ D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE,		D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_NAME			},
	{ D_RECEIVED_SUPERMAN_SK_INVALIDATE,				D_RECEIVED_SUPERMAN_SK_INVALIDATE_NAME					},
	{ D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE,			D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_NAME				},
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

// K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY
enum {
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE,
	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP,
	__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX,
#define K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX (__K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX - 1)
};
typedef struct k_update_superman_security_table_entry_msg {
	uint32_t	address;
	uint8_t		flag;
	uint32_t	sk_len;
	unsigned char*	sk;
	uint32_t	ske_len;
	unsigned char*	ske;
	uint32_t	skp_len;
	unsigned char*	skp;
} k_update_superman_security_table_entry_msg_t;
static struct nla_policy k_update_superman_security_table_entry_genl_policy[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX + 1] = {
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG] 					= 	{ .type = NLA_U8		},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK]					=	{ .type = NLA_UNSPEC	},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE]					=	{ .type = NLA_UNSPEC	},
	[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP]					=	{ .type = NLA_UNSPEC	},
};

// K_UPDATE_SUPERMAN_BROADCAST_KEY
enum {
	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_KEY,
	__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX,
#define K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX (__K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX - 1)
};
typedef struct k_update_superman_broadcast_key_msg {
	uint32_t	broadcast_key_len;
	unsigned char*	broadcast_key;
} k_update_superman_broadcast_key_msg_t;
static struct nla_policy k_update_superman_broadcast_key_genl_policy[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX + 1] = {
	[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_KEY]					=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_DISCOVERY_REQUEST
enum {
	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,
	__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX,
#define K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX - 1)
};
typedef struct k_send_superman_discovery_request_msg {
	uint32_t	sk_len;
	unsigned char*	sk;
} k_send_superman_discovery_request_msg_t;
static struct nla_policy k_send_superman_discovery_request_genl_policy[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]						=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_CERTIFICATE_REQUEST
enum {
	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,
	__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX,
#define K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX - 1)
};
typedef struct k_send_superman_certificate_request_msg {
	uint32_t	address;
	uint32_t	sk_len;
	unsigned char*	sk;
} k_send_superman_certificate_request_msg_t;
static struct nla_policy k_send_superman_certificate_request_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]						=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE
enum {
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX,
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX - 1)
};
typedef struct k_send_superman_certificate_exchange_msg {
	uint32_t	address;
	uint32_t	certificate_len;
	unsigned char*	certificate;
} k_send_superman_certificate_exchange_msg_t;
static struct nla_policy k_send_superman_certificate_exchange_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]					=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY
enum {
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,
	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY,
	__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX,
#define K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX (__K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX - 1)
};
typedef struct k_send_superman_certificate_exchange_with_broadcast_key_msg {
	uint32_t	address;
	uint32_t	certificate_len;
	unsigned char*	certificate;
	uint32_t	broadcast_key_len;
	unsigned char*	broadcast_key;
} k_send_superman_certificate_exchange_with_broadcast_key_msg_t;
static struct nla_policy k_send_superman_certificate_exchange_with_broadcast_key_genl_policy[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]			=	{ .type = NLA_U32		},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]		=	{ .type = NLA_UNSPEC	},
	[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY]		=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE
enum {
	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,
	__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX,
#define K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX (__K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX - 1)
};
typedef struct k_send_superman_broadcast_key_exchange_msg {
	uint32_t	broadcast_key_len;
	unsigned char*	broadcast_key;
} k_send_superman_broadcast_key_exchange_msg_t;
static struct nla_policy k_send_superman_broadcast_key_exchange_genl_policy[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]				=	{ .type = NLA_UNSPEC	},
};

// K_SEND_SUPERMAN_SK_INVALIDATE
enum {
	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,
	__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX,
#define K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX (__K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX - 1)
};
typedef struct k_send_superman_sk_invalidate_msg {
	uint32_t	address;
} k_send_superman_sk_invalidate_msg_t;
static struct nla_policy k_send_superman_sk_invalidate_genl_policy[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX + 1] = {
	[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]						=	{ .type = NLA_U32		},
};

// D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST
enum {
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,
	__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX (__D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX - 1)
};
typedef struct d_received_superman_discovery_request_msg {
	uint32_t	address;
	uint32_t	sk_len;
	unsigned char*	sk;
} d_received_superman_discovery_request_msg_t;
static struct nla_policy d_received_superman_discovery_request_genl_policy[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]						=	{ .type = NLA_UNSPEC	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST
enum {
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX - 1)
};
typedef struct d_received_superman_certificate_request_msg {
	uint32_t	address;
	uint32_t	sk_len;
	unsigned char*	sk;
} d_received_superman_certificate_request_msg_t;
static struct nla_policy d_received_superman_certificate_request_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]					=	{ .type = NLA_UNSPEC	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE
enum {
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX - 1)
};
typedef struct d_received_superman_certificate_exchange_msg {
	uint32_t	address;
	uint32_t	certificate_len;
	unsigned char*	certificate;
} d_received_superman_certificate_exchange_msg_t;
static struct nla_policy d_received_superman_certificate_exchange_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]					=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]				=	{ .type = NLA_UNSPEC	},
};

// D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY
enum {
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,
	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY,
	__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX (__D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX - 1)
};
typedef struct d_received_superman_certificate_exchange_with_broadcast_key_msg {
	uint32_t	address;
	uint32_t	certificate_len;
	unsigned char*	certificate;
	uint32_t	broadcast_key_len;
	unsigned char*	broadcast_key;
} d_received_superman_certificate_exchange_with_broadcast_key_msg_t;
static struct nla_policy d_received_superman_certificate_exchange_with_broadcast_key_genl_policy[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]		=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]		=	{ .type = NLA_UNSPEC	},
	[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY]	=	{ .type = NLA_UNSPEC	},
};

// D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE
enum {
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS,
	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK,
	__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX (__D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX - 1)
};
typedef struct d_received_superman_authenticated_sk_response_msg {
	uint32_t	address;
	uint32_t	sk_len;
	unsigned char*	sk;
} d_received_superman_certificate_authenticated_sk_response_msg_t;
static struct nla_policy d_received_superman_authenticated_sk_response_genl_policy[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS]			=	{ .type = NLA_U32		},
	[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK]				=	{ .type = NLA_UNSPEC	},
};

// D_RECEIVED_SUPERMAN_SK_INVALIDATE
enum {
	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,
	__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX (__D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX - 1)
};
typedef struct d_received_superman_sk_invalidate_msg {
	uint32_t	address;
} d_received_supermandsk_invalidate_msg_t;
static struct nla_policy d_received_superman_sk_invalidate_genl_policy[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]				=	{ .type = NLA_U32		},
};

// D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE
enum {
	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,
	__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX,
#define D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX (__D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX - 1)
};
typedef struct d_received_superman_broadcast_key_exchange_msg {
	uint32_t	broadcast_key_len;
	unsigned char*	broadcast_key;
} d_received_superman_broadcast_key_exchange_msg_t;
static struct nla_policy d_received_superman_broadcast_key_exchange_genl_policy[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX + 1] = {
	[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]			=	{ .type = NLA_U32		},
};



#ifdef __KERNEL__

static struct genl_family superman_genl_family = {
	.id			= 0, 	// GENL_ID_GENERATE = 0
	.hdrsize		= 0,
	.name			= K_SUPERMAN_FAMILY_NAME,
	.version		= 1,
	.maxattr		= K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX, //SUPERMAN_ATTR_MAX,
};

enum {
	K_SUPERMAN_MC_GROUP,
#define K_SUPERMAN_MC_GROUP K_SUPERMAN_MC_GROUP

	__K_SUPERMAN_MC_GROUP_MAX,
#define K_SUPERMAN_MC_GROUP_MAX __K_SUPERMAN_MC_GROUP_MAX
};

static struct genl_multicast_group superman_mc_groups[K_SUPERMAN_MC_GROUP_MAX] = {
	{
		.name		= K_SUPERMAN_MC_GROUP_NAME,
	},
};

#define GENL_PARSE(ATTR_MAX, POLICY) \
	struct nlattr *attrs[ATTR_MAX + 1]; \
	if(nlmsg_parse(info->nlhdr, superman_genl_family.hdrsize + GENL_HDRLEN, attrs, ATTR_MAX, POLICY) < 0) \
	{ \
		printk(KERN_INFO "Netlink: Failed to parse netlink message\n"); \
		return 0; \
	}

int k_update_superman_security_table_entry(struct sk_buff *skb_msg, struct genl_info *info)
{

	uint32_t	address;
	uint8_t		flag;
	uint32_t	sk_len;
	unsigned char*	sk;
	uint32_t	ske_len;
	unsigned char*	ske;
	uint32_t	skp_len;
	unsigned char*	skp;
	GENL_PARSE(K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_MAX, k_update_superman_security_table_entry_genl_policy)
	address = nla_get_u32(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS]);
	flag = nla_get_u8(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG]);
	sk_len = nla_len(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK]);
	sk = kmalloc(sk_len, GFP_KERNEL);
	nla_memcpy(sk, attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK], sk_len);
	ske_len = nla_len(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE]);
	ske = kmalloc(ske_len, GFP_KERNEL);
	nla_memcpy(ske, attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE], ske_len);
	skp_len = nla_len(attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP]);
	skp = kmalloc(skp_len, GFP_KERNEL);
	nla_memcpy(skp, attrs[K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP], skp_len);

	// Update the security table

	kfree(sk);
	kfree(ske);
	kfree(skp);

	return 0;
}

int k_update_superman_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;
	GENL_PARSE(K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_MAX, k_update_superman_broadcast_key_genl_policy)
	broadcast_key_len = nla_len(attrs[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_KEY]);
	broadcast_key = kmalloc(broadcast_key_len, GFP_KERNEL);
	nla_memcpy(broadcast_key, attrs[K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_KEY], broadcast_key_len);

	// Do something with the broadcast key!

	kfree(broadcast_key);

	return 0;
}

int k_send_superman_discovery_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t sk_len;
	unsigned char* sk;
	GENL_PARSE(K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX, k_send_superman_discovery_request_genl_policy)
	sk_len = nla_len(attrs[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]);
	sk = kmalloc(sk_len, GFP_KERNEL);
	nla_memcpy(sk, attrs[K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK], sk_len);

	SendDiscoveryRequest(sk_len, sk);

	kfree(sk);

	return 0;
}

int k_send_superman_certificate_request(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t address;
	uint32_t sk_len;
	unsigned char* sk;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX, k_send_superman_certificate_request_genl_policy)
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]);
	sk_len = nla_len(attrs[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]);
	sk = kmalloc(sk_len, GFP_KERNEL);
	nla_memcpy(sk, attrs[K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK], sk_len);

	// Do something with the request!

	kfree(sk);

	return 0;
}

int k_send_superman_certificate_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t address;
	uint32_t certificate_len;
	unsigned char* certificate;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX, k_send_superman_certificate_exchange_genl_policy)
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]);
	certificate_len = nla_len(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]);
	certificate = kmalloc(certificate_len, GFP_KERNEL);
	nla_memcpy(certificate, attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE], certificate_len);

	// Do something with the exchange!

	kfree(certificate);

	return 0;
}

int k_send_superman_certificate_exchange_with_broadcast_key(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t address;
	uint32_t certificate_len;
	unsigned char* certificate;
	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;
	GENL_PARSE(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX, k_send_superman_certificate_exchange_with_broadcast_key_genl_policy)
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]);
	certificate_len = nla_len(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]);
	certificate = kmalloc(certificate_len, GFP_KERNEL);
	nla_memcpy(certificate, attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE], certificate_len);
	broadcast_key_len = nla_len(attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY]);
	broadcast_key = kmalloc(broadcast_key_len, GFP_KERNEL);
	nla_memcpy(broadcast_key, attrs[K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY], broadcast_key_len);

	// Do something with the exchange!

	kfree(certificate);
	kfree(broadcast_key);

	return 0;
}

int k_send_superman_broadcast_key_exchange(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;
	GENL_PARSE(K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX, k_send_superman_broadcast_key_exchange_genl_policy)
	broadcast_key_len = nla_len(attrs[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]);
	broadcast_key = kmalloc(broadcast_key_len, GFP_KERNEL);
	nla_memcpy(broadcast_key, attrs[K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY], broadcast_key_len);

	// Do something with the exchange!

	kfree(broadcast_key);

	return 0;
}

int k_send_superman_sk_invalidate(struct sk_buff *skb_msg, struct genl_info *info)
{
	uint32_t address;
	GENL_PARSE(K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_MAX, k_send_superman_sk_invalidate_genl_policy)
	address = nla_get_u32(attrs[K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]);

	// Do something with the request!

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

#define GENL_PARSE(ATTR_MAX, POLICY) \
	struct nlattr *attrs[ATTR_MAX + 1]; \
	if(genlmsg_parse(nlh, 0, attrs, ATTR_MAX, POLICY) < 0) \
	{ \
		printf("Netlink: Failed to parse netlink message\n"); \
		return NL_SKIP; \
	}

int d_received_superman_discovery_request(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_MAX, d_received_superman_discovery_request_genl_policy)

	uint32_t address;
	uint32_t sk_len;
	unsigned char* sk;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS]);
	sk_len = nla_len(attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK]);
	sk = malloc(sk_len);
	nla_memcpy(sk, attrs[D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK], sk_len);

	// Do something with the request!

	free(sk);

	return 0;
}

int d_received_superman_certificate_request(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_MAX, d_received_superman_certificate_request_genl_policy)

	uint32_t address;
	uint32_t sk_len;
	unsigned char* sk;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS]);
	sk_len = nla_len(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK]);
	sk = malloc(sk_len);
	nla_memcpy(sk, attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK], sk_len);

	// Do something with the request!

	free(sk);

	return 0;
}

int d_received_superman_certificate_exchange(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_MAX, d_received_superman_certificate_exchange_genl_policy)

	uint32_t address;
	uint32_t certificate_len;
	unsigned char* certificate;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS]);
	certificate_len = nla_len(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE]);
	certificate = malloc(certificate_len);
	nla_memcpy(certificate, attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE], certificate_len);

	// Do something with the exchange!

	free(certificate);

	return 0;
}

int d_received_superman_certificate_exchange_with_broadcast_key(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_MAX, d_received_superman_certificate_exchange_with_broadcast_key_genl_policy)

	uint32_t address;
	uint32_t certificate_len;
	unsigned char* certificate;
	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS]);
	certificate_len = nla_len(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE]);
	certificate = malloc(certificate_len);
	nla_memcpy(certificate, attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE], certificate_len);
	broadcast_key_len = nla_len(attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY]);
	broadcast_key = malloc(broadcast_key_len);
	nla_memcpy(broadcast_key, attrs[D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY], broadcast_key_len);

	// Do something with the exchange!

	free(certificate);
	free(broadcast_key);

	return 0;
}

int d_received_superman_authenticated_sk_response(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_MAX, d_received_superman_authenticated_sk_response_genl_policy)

	uint32_t address;
	uint32_t sk_len;
	unsigned char* sk;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS]);
	sk_len = nla_len(attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK]);
	sk = malloc(sk_len);
	nla_memcpy(sk, attrs[D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK], sk_len);

	// Do something with the sk!

	free(sk);

	return 0;
}

int d_received_superman_sk_invalidate(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_MAX, d_received_superman_sk_invalidate_genl_policy)

	uint32_t address;

	address = nla_get_u32(attrs[D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS]);

	// Do something with the request!

	return 0;
}

int d_received_superman_broadcast_key_exchange(struct nlmsghdr *nlh)
{
	GENL_PARSE(D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_MAX, d_received_superman_broadcast_key_exchange_genl_policy)

	uint32_t broadcast_key_len;
	unsigned char* broadcast_key;

	broadcast_key_len = nla_len(attrs[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY]);
	broadcast_key = malloc(broadcast_key_len);
	nla_memcpy(broadcast_key, attrs[D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY], broadcast_key_len);

	// Do something with the exchange!

	free(broadcast_key);

	return 0;
}

int d_superman_messaging_callback(struct nl_msg* msg, void* arg)
{
	struct nlmsghdr *nlh = NULL;
	struct genlmsghdr* genlh = NULL;

	nlh = nlmsg_hdr(msg);
	if(!nlh)
	{
		printf("Netlink: Failed to get the Netlink message header\n");
		return NL_SKIP;
	}

	genlh = genlmsg_hdr(nlh);
	if(!genlh)
	{
		printf("Netlink: Failed to get the Generic Netlink message header\n");
		return NL_SKIP;
	}

	switch(genlh->cmd)
	{
		case D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST:
			return d_received_superman_discovery_request(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST:
			return d_received_superman_certificate_request(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE:
			return d_received_superman_certificate_exchange(nlh);
			break;
		case D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY:
			return d_received_superman_certificate_exchange_with_broadcast_key(nlh);
			break;
		case D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE:
			return d_received_superman_authenticated_sk_response(nlh);
			break;
		case D_RECEIVED_SUPERMAN_SK_INVALIDATE:
			return d_received_superman_sk_invalidate(nlh);
			break;
		case D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE:
			return d_received_superman_broadcast_key_exchange(nlh);
			break;
	}

	return NL_SKIP;
}

void CheckForMessages(void)
{
	if(nlsk)
	{
		int rc = 0;

		// Receive messages
		rc = nl_recvmsgs_default(nlsk);
		if(rc < 0)
		{
			printf("Netlink: nl_recvmsgs_default failed, rc %d\n", rc);
			DeInitNetlink();
		}
	}
}

#endif

#ifdef __KERNEL__

static struct genl_ops superman_ops[SUPERMAN_MAX] = {

	// Daemon to Kernel functions

	{
		.cmd		= K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY,
		.flags		= 0,
		.policy		= k_update_superman_security_table_entry_genl_policy,
		.doit		= k_update_superman_security_table_entry,
		.dumpit		= NULL,
	}, {
		.cmd		= K_UPDATE_SUPERMAN_BROADCAST_KEY,
		.flags		= 0,
		.policy		= k_update_superman_broadcast_key_genl_policy,
		.doit		= k_update_superman_broadcast_key,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_DISCOVERY_REQUEST,
		.flags		= 0,
		.policy		= k_send_superman_discovery_request_genl_policy,
		.doit		= k_send_superman_discovery_request,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_CERTIFICATE_REQUEST,
		.flags		= 0,
		.policy		= k_send_superman_certificate_request_genl_policy,
		.doit		= k_send_superman_certificate_request,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE,
		.flags		= 0,
		.policy		= k_send_superman_certificate_exchange_genl_policy,
		.doit		= k_send_superman_certificate_exchange,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,
		.flags		= 0,
		.policy		= k_send_superman_certificate_exchange_with_broadcast_key_genl_policy,
		.doit		= k_send_superman_certificate_exchange_with_broadcast_key,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE,
		.flags		= 0,
		.policy		= k_send_superman_broadcast_key_exchange_genl_policy,
		.doit		= k_send_superman_broadcast_key_exchange,
		.dumpit		= NULL,
	}, {
		.cmd		= K_SEND_SUPERMAN_SK_INVALIDATE,
		.flags		= 0,
		.policy		= k_send_superman_sk_invalidate_genl_policy,
		.doit		= k_send_superman_sk_invalidate,
		.dumpit		= NULL,
	},

	// Kernel to Daemon functions
	{
		.cmd       	= D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST,
		.flags		= 0,
		.policy  	= d_received_superman_discovery_request_genl_policy,
		.doit		= d_received_superman_discovery_request,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST,
		.flags		= 0,
		.policy  	= d_received_superman_certificate_request_genl_policy,
		.doit		= d_received_superman_certificate_request,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE,
		.flags		= 0,
		.policy  	= d_received_superman_certificate_exchange_genl_policy,
		.doit		= d_received_superman_certificate_exchange,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY,
		.flags		= 0,
		.policy  	= d_received_superman_certificate_exchange_with_broadcast_key_genl_policy,
		.doit		= d_received_superman_certificate_exchange_with_broadcast_key,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE,
		.flags		= 0,
		.policy  	= d_received_superman_authenticated_sk_response_genl_policy,
		.doit		= d_received_superman_authenticated_sk_response,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_SK_INVALIDATE,
		.flags		= 0,
		.policy  	= d_received_superman_sk_invalidate_genl_policy,
		.doit		= d_received_superman_sk_invalidate,
		.dumpit 	= NULL,
	}, {
		.cmd 		= D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE,
		.flags		= 0,
		.policy  	= d_received_superman_broadcast_key_exchange_genl_policy,
		.doit		= d_received_superman_broadcast_key_exchange,
		.dumpit 	= NULL,
	},
};

#endif



#ifndef __KERNEL__

#define D_GENL_START(K_SUPERMAN_OPERATION) \
	struct nl_msg *msg; \
	int superman_family_id; \
	int fail = 0; \
	\
	/* Find the SUPERMAN family identifier. */ \
	superman_family_id = genl_ctrl_resolve(nlsk, K_SUPERMAN_FAMILY_NAME); \
	\
	if(superman_family_id >= 0) \
	{ \
		/* Construct a new message */ \
		msg = nlmsg_alloc(); \
		\
		/* Add the Generic Netlink header to the netlink message. */ \
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, superman_family_id, 0, 0, K_SUPERMAN_OPERATION, 0); \

#define D_GENL_FINISH \
		if(fail == 0) { \
			/* Send the message over the netlink socket */ \
			nl_send_auto(nlsk, msg); \
		} \
		\
		/* Cleanup */ \
		nlmsg_free(msg); \
	} \
	else {\
		printf("Netlink: No SUPERMAN netlink family found. Is the SUPERMAN kernel module loaded?\n"); \
	}

void UpdateSupermanSecurityTableEntry(uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp)
{
	D_GENL_START(K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY)
	if(	nla_put_u32	(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_ADDRESS,							address		) ||
		nla_put_u8	(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_FLAG,							flag		) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SK,					sk_len,			sk		) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKE,				ske_len,		skp		) ||
		nla_put		(msg,	K_UPDATE_SUPERMAN_SECURITY_TABLE_ENTRY_ATTR_SKP,				ske_len,		skp		))
		fail = 1;
	D_GENL_FINISH
}

void UpdateSupermanBroadcastKey(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	D_GENL_START(K_UPDATE_SUPERMAN_BROADCAST_KEY)
	if(	nla_put		(msg,	K_UPDATE_SUPERMAN_BROADCAST_KEY_ATTR_BROADCAST_KEY,				broadcast_key_len,	broadcast_key	))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanDiscoveryRequest(uint32_t sk_len, unsigned char* sk)
{
	D_GENL_START(K_SEND_SUPERMAN_DISCOVERY_REQUEST)
	if(	nla_put		(msg,	K_SEND_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,					sk_len,			sk		))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_REQUEST)
	if(	nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,							address		) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,					sk_len,			sk		))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE)
	if(	nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,							address		) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,				certificate_len,	certificate	))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	D_GENL_START(K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY)
	if(	nla_put_u32	(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,					address		) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,	certificate_len,	certificate	) ||
		nla_put		(msg,	K_SEND_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,	broadcast_key_len,	broadcast_key	))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	D_GENL_START(K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE)
	if(	nla_put		(msg,	K_SEND_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,			broadcast_key_len, 	broadcast_key	))
		fail = 1;
	D_GENL_FINISH
}

void SendSupermanSKInvalidate(uint32_t address)
{
	D_GENL_START(K_SEND_SUPERMAN_SK_INVALIDATE)
	if(	nla_put_u32	(msg,	K_SEND_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,								address		))
		fail = 1;
	D_GENL_FINISH
}

#else

#define K_GENL_START(D_SUPERMAN_OPERATION) \
	struct sk_buff* skb; \
	void* msg; \
	int fail = 0; \
	\
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL); \
	if(!skb) { \
		printk(KERN_INFO "SUPERMAN: Netlink message construction failure.\n"); \
		return; \
	} \
	\
	msg = genlmsg_put( skb, \
	                   0,           		/* PID is whatever */ \
	                   0,           		/* Sequence number (don't care) */ \
	                   &superman_genl_family,   	/* Pointer to family struct */ \
	                   0,                     	/* Flags */ \
	                   D_SUPERMAN_OPERATION 	/* Generic netlink command */ \
	                   ); \
	if(!msg) { \
		printk(KERN_INFO "SUPERMAN: Generic Netlink message construction failure.\n"); \
		return; \
	} \

#define K_GENL_FINISH \
	\
	if(fail == 1) { \
		genlmsg_cancel(skb, msg); \
	} else { \
		/* Finalise the message */ \
		genlmsg_end(skb, msg); \
		\
		fail = genlmsg_multicast_allns(&superman_genl_family, skb, 0, 0, GFP_KERNEL); \
		\
		/*	If error - fail.
			ESRCH is "forever alone" case - no one is listening for our messages 
			and it's ok, since userspace daemon can be unloaded.
		*/ \
		if(fail && fail != -ESRCH) \
		{ \
			printk(KERN_INFO "Failed to send message. fail = %d\n", fail); \
			genlmsg_cancel(skb, msg); \
		} \
	} \
	/* Need this to free notification allocated in irq handler */ \
	kfree(skb); \
	
void ReceivedSupermanDiscoveryRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_ADDRESS,							address		) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_DISCOVERY_REQUEST_ATTR_SK,					sk_len,			sk		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_ADDRESS,							address		) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_REQUEST_ATTR_SK,				sk_len,			sk		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_ADDRESS,							address		) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_ATTR_CERTIFICATE,			certificate_len,	certificate	))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanCertificateExchangeWithBroadcasstKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_ADDRESS,				address		) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_CERTIFICATE,	certificate_len,	certificate	) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_ATTR_BROADCAST_KEY,	broadcast_key_len,	broadcast_key	))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_ADDRESS,						address		) ||
		nla_put		(skb,	D_RECEIVED_SUPERMAN_AUTHENTICATED_SK_RESPONSE_ATTR_SK,				sk_len,			sk		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanSKInvalidate(uint32_t address)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_SK_INVALIDATE)
	if(	nla_put_u32	(skb,	D_RECEIVED_SUPERMAN_SK_INVALIDATE_ATTR_ADDRESS,								address		))
		fail = 1;
	K_GENL_FINISH
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	K_GENL_START(D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE)
	if(	nla_put		(skb,	D_RECEIVED_SUPERMAN_BROADCAST_KEY_EXCHANGE_ATTR_BROADCAST_KEY,			broadcast_key_len,	broadcast_key	))
		fail = 1;
	K_GENL_FINISH
}

#endif

bool InitNetlink(void)
{
#ifdef __KERNEL__
	genl_register_family_with_ops_groups(&superman_genl_family, superman_ops, superman_mc_groups);
#else
	int rc = 0;

	// Allocate a new socket
	nlsk = nl_socket_alloc();
	if(!nlsk) {
		printf("Netlink: nl_socket_alloc failed\n" );
		return false;
	}

	// Disable sequence number checking
	nl_socket_disable_seq_check(nlsk);

	// Entry callback for valid incoming messages
	rc = nl_socket_modify_cb(nlsk, NL_CB_VALID, NL_CB_CUSTOM, d_superman_messaging_callback, NULL);
	if(rc < 0)
	{
		printf("Netlink: nl_cb_set failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// Connect to Generic Netlink bus
	rc = genl_connect(nlsk);
	if(rc < 0)
	{
		printf("Netlink: genl_connect failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}

	// Allocate libnl generic netlink cache
	rc = genl_ctrl_alloc_cache(nlsk, &genl_cache);
	if(rc < 0)
	{
		printf("Netlink: genl_ctrl_alloc_cache failed, rc %d\n", rc);
		DeInitNetlink();
		return false;
	}
	
	// Resolve keymon muilticast group 
	superman_mc_group_id = genl_ctrl_resolve_grp(nlsk, K_SUPERMAN_FAMILY_NAME, K_SUPERMAN_MC_GROUP_NAME);
	if(superman_mc_group_id < 0)
	{
		printf("Netlink: genl_ctrl_resolve_grp failed, rc %d\n", superman_mc_group_id);
		DeInitNetlink();
		return false;
	}

	// Join keymon multicast group
	rc = nl_socket_add_memberships(nlsk, superman_mc_group_id, 0);
	if ( rc < 0 )
	{
		printf("Netlink: nl_socket_add_membership failed, rc %d\n", rc);
		superman_mc_group_id = -1;
		DeInitNetlink();
		return false;
	}

#endif
	return true;
}

void DeInitNetlink(void)
{
#ifdef __KERNEL__
	genl_unregister_family(&superman_genl_family);
#else
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
}

