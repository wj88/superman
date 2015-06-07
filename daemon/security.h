#ifndef __SUPERMAN_SECURITY_H
#define __SUPERMAN_SECURITY_H

#include "superman.h"

bool GetCertificate(void** certificate, int* certificate_len);
bool VerifyCertificate(char* cert_data);

#endif

