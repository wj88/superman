#ifndef __SUPERMAN_NETLINK_H
#define __SUPERMAN_NETLINK_H

#include "superman.h"

#ifndef __KERNEL__

#include <stdint.h>

bool CheckForMessages(void);

void UpdateSupermanSecurityTableEntry(uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp);
void UpdateSupermanBroadcastKey(uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendSupermanDiscoveryRequest(uint32_t sk_len, unsigned char* sk);
void SendSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk);
void SendSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate);
void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key);
void SendSupermanSKInvalidate(uint32_t address);

#else

void ReceivedSupermanDiscoveryRequest(uint32_t address, uint32_t sk_len, unsigned char* sk);
void ReceivedSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk);
void ReceivedSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate);
void ReceivedSupermanCertificateExchangeWithBroadcasstKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key);
void ReceivedSupermanAuthenticatedSKResponse(uint32_t address, uint32_t sk_len, unsigned char* sk);
void ReceivedSupermanSKInvalidate(uint32_t address);
void ReceivedSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key);

#endif

bool InitNetlink(void);
void DeInitNetlink(void);

#endif

