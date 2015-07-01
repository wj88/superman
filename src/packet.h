#ifndef _SUPERMAN_PACKET_H
#define _SUPERMAN_PACKET_H

#ifdef __KERNEL__

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
};
#pragma pack(pop)


inline bool is_superman_packet(struct sk_buff* skb);
inline struct superman_header* get_superman_header(struct sk_buff *skb);

bool EncapsulatePacket(struct superman_packet_info* spi);
bool DecapsulatePacket(struct superman_packet_info* spi);

void SendDiscoveryRequestPacket(uint32_t sk_len, unsigned char* sk);
void SendCertificateRequestPacket(uint32_t addr, uint32_t sk_len, unsigned char* sk);
void SendCertificateExchangePacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate);
void SendCertificateExchangeWithBroadcastKeyPacket(uint32_t addr, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendAuthenticatedSKRequestPacket(uint32_t addr);

void SendInvalidateSKPacket(uint32_t addr);

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
