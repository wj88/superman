#ifndef __SUPERMAN_PROCESSOR_H
#define __SUPERMAN_PROCESSOR_H

#include "superman.h"

#ifdef __KERNEL__

void LoadNodeCertificateAndSecureInterface(uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename, uint32_t interface_name_len, unsigned char* interface_name);
void SecureInterface(uint32_t ifindex);
void SecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name);
void UnsecureInterface(uint32_t ifindex);
void UnsecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name);
void UnloadAll(void);
void UpdateSupermanSecurityTableEntry(uint32_t ifindex, uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp);
void UpdateSupermanBroadcastKey(uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite);
void TriggerSupermanDiscoveryRequest(void);
void SendSupermanDiscoveryRequest(uint32_t ifindex, uint32_t sk_len, unsigned char* sk);
void SendSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk);
void SendSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate);
void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate);
void SendSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key, bool only_if_changed);
void SendSupermanSKInvalidate(uint32_t ifindex, uint32_t address);

#else

#include <stdint.h>

void LoadNodeCertificateThenSecureInterface(uint32_t ifindex, uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename);
void RaiseSupermanDiscoveryRequest(uint32_t ifindex);
void RaiseNewBroadcastKey(uint32_t ifindex);
void ReceivedSupermanDiscoveryRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp);
void ReceivedSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp);
void ReceivedSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate);
void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key);
void ReceivedSupermanAuthenticatedSKResponse(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp);
void ReceivedSupermanSKInvalidate(uint32_t ifindex, uint32_t address);
void ReceivedSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key);

#endif

#endif
