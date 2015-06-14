#ifndef __SUPERMAN_SECURITY_H
#define __SUPERMAN_SECURITY_H

#ifndef __KERNEL__

#include "superman.h"

bool MallocAndCopyPublickey(uint32_t* sk_len, unsigned char** sk);
bool MallocAndCopyCertificate(uint32_t* certificate_len, unsigned char** certificate);
bool MallocAndCopySharedkeys(uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp);
bool MallocAndCopyNewKey(uint32_t* key_len, unsigned char** key);

bool VerifyCertificate(unsigned char* cert_data, unsigned char* node_share, int node_share_len);
bool TestCertificate(unsigned char* cert_filename);
bool InitSecurity(unsigned char* ca_cert_filename, unsigned char* node_cert_filename, unsigned char* node_dh_privatekey_filename);
void DeInitSecurity();

#endif

#endif
