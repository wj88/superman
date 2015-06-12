#ifndef __SUPERMAN_SECURITY_H
#define __SUPERMAN_SECURITY_H

#include "superman.h"

bool VerifyCertificate(unsigned char* cert_data, unsigned char* node_share, int node_share_len);
bool TestCertificate(unsigned char* cert_filename);
bool InitSecurity(unsigned char* ca_cert_filename, unsigned char* node_cert_filename, unsigned char* node_dh_privatekey_filename);
void DeInitSecurity();

#endif

