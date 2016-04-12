#ifndef _SUPERMAN_PACKET_H
#define _SUPERMAN_PACKET_H

#ifdef __KERNEL__

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <asm/byteorder.h>

#include "superman.h"
#include "packet_info.h"


enum {
	SUPERMAN_DISCOVERY_REQUEST_TYPE = 1,
#define SUPERMAN_DISCOVERY_REQUEST_TYPE SUPERMAN_DISCOVERY_REQUEST_TYPE

	SUPERMAN_CERTIFICATE_REQUEST_TYPE = 2,
#define SUPERMAN_CERTIFICATE_REQUEST_TYPE SUPERMAN_CERTIFICATE_REQUEST_TYPE

	SUPERMAN_CERTIFICATE_EXCHANGE_TYPE = 3,
#define SUPERMAN_CERTIFICATE_EXCHANGE_TYPE SUPERMAN_CERTIFICATE_EXCHANGE_TYPE

	SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE = 4,
#define SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE SUPERMAN_CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_TYPE

	SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE = 5,
#define SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE SUPERMAN_AUTHENTICATED_SK_REQUEST_TYPE

	SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE = 6,
#define SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE SUPERMAN_AUTHENTICATED_SK_RESPONSE_TYPE

	SUPERMAN_SK_INVALIDATE_TYPE = 7,
#define SUPERMAN_SK_INVALIDATE_TYPE SUPERMAN_SK_INVALIDATE_TYPE

	SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE = 8,
#define SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE SUPERMAN_BROADCAST_KEY_EXCHANGE_TYPE

	__SUPERMAN_MAX_TYPE,
#define SUPERMAN_MAX_TYPE (__SUPERMAN_MAX_TYPE - 1)
};

// We need 1 byte alignment, otherwise the header size ends up being 6 bytes big, rather than 5.
#pragma pack(push)
#pragma pack(1)
struct superman_header {
	__u8	type;
	__be16	timestamp;
	__be16	payload_len;
	__be32	last_addr;
};
#define SUPERMAN_HEADER_LEN sizeof(struct superman_header)

struct certificate_exchange_payload {
	//     2 bytes      | certificate_len
	// -----------------------------------
	//  certificate_len |   certificate    
	// -----------------------------------
	__be16		certificate_len;
	unsigned char	certificate[0];
};
#define CERTIFICATE_EXCHANGE_PAYLOAD_LEN(certificate_len) (sizeof(struct certificate_exchange_payload) + certificate_len)

struct certificate_exchange_with_broadcast_key_payload {
	//      2 bytes     |     2 bytes       |  certificate_len     | broadcast_key_len
	// --------------------------------------------------------------------------------
	//   certificte_len | broadcast_key_len |    certificate       |   broadcast_key       
	// --------------------------------------------------------------------------------
	__be16		certificate_len;
	__be16		broadcast_key_len;
	unsigned char	data[0];
};
#define CERTIFICATE_EXCHANGE_WITH_BROADCAST_KEY_PAYLOAD_LEN(certificate_len, broadcast_key_len) (sizeof(struct certificate_exchange_with_broadcast_key_payload) + certificate_len + broadcast_key_len)


struct sk_request_payload {
	//    4 bytes    |   4 bytes  
	// -----------------------------
	//   originaddr  |  targetaddr   
	// -----------------------------
	__be32		originaddr;
	__be32		targetaddr;
};
#define SK_REQUEST_PAYLOAD_LEN sizeof(struct sk_request_payload)

struct sk_response_payload {
	//    4 bytes   |  4 bytes   | 2 bytes | sk_len    
	// -----------------------------------------
	//   originaddr | targetaddr |  sk_len |  sk   
	// -----------------------------------------
	__be32		originaddr;
	__be32		targetaddr;
	__be16		sk_len;
	unsigned char	sk[0];
};
#define SK_RESPONSE_PAYLOAD_LEN(sk_len) (sizeof(struct sk_response_payload) + sk_len)

struct broadcast_key_exchange_payload {
	__be16		broadcast_key_len;
	unsigned char	broadcast_key[0];
};
#define BROADCAST_KEY_EXCHANGE_PAYLOAD_LEN(broadcast_key_len) (sizeof(struct broadcast_key_exchange_payload) + broadcast_key_len)

struct sk_invalidate_payload {
	__be32		addr;
};
#define SK_INVALIDATE_PAYLOAD_LEN sizeof(struct sk_invalidate_payload)

#pragma pack(pop)

inline bool if_info_from_net_device(__be32* addr, __be32* baddr, const struct net_device *dev);
inline const char* lookup_superman_packet_type_desc(__u8 type);
inline bool is_superman_packet(struct sk_buff* skb);
inline struct superman_header* get_superman_header(struct sk_buff *skb);

bool EncapsulatePacket(struct superman_packet_info* spi);
bool DecapsulatePacket(struct superman_packet_info* spi);

void SendDiscoveryRequestPacket(uint32_t sk_len, unsigned char* sk);
void SendCertificateRequestPacket(uint32_t addr, uint32_t sk_len, unsigned char* sk);
void SendCertificateExchangePacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate);
void SendCertificateExchangeWithBroadcastKeyPacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendAuthenticatedSKRequestPacket(uint32_t originaddr, uint32_t targetaddr);
void SendAuthenticatedSKResponsePacket(uint32_t originaddr, uint32_t targetaddr, uint32_t sk_len, unsigned char* sk);

void SendBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendSKInvalidatePacket(uint32_t addr);

/*
void SendCertificateRequest(struct sk_buff* rx_sk);
void SendCertificateResponse(struct sk_buff* rx_sk);
bool ReceiveCertificateExchange(struct sk_buff* rx_sk);
bool HaveSK(struct sk_buff* rx_sk);
void SendAuthenticatedSKRequest(struct sk_buff* sk);
void SendAuthenticatedSKResponse(struct sk_buff* rx_sk);
bool ReceiveAuthenticatedSKResponse(struct sk_buff* rx_sk);
void InvalidateSK(struct sk_buff* rx_sk);
bool SendP2PPacket(struct sk_buff* tx_sk);
bool SendE2EPacket(struct sk_buff* tx_sk);
bool ReceiveP2PPacket(struct sk_buff* rx_sk);
bool ReceiveE2EPacket(struct sk_buff* rx_sk);
*/

//struct sk_buff* EncapsulateSupermanPacket(struct sk_buff *skb, u_int8_t type, u_int16_t timestamp);
//struct sk_buff* DecapsulateSupermanPacket(struct sk_buff *skb);

#endif

#endif
