#include "superman.h"
#include "processor.h"
#include "netlink.h"

#ifdef __KERNEL__

#include "security_table.h"
#include "packet.h"
#include "security.h"

void UpdateSupermanSecurityTableEntry(uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp, int32_t ifindex)
{
	UpdateOrAddSecurityTableEntry(address, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);
}

void UpdateSupermanBroadcastKey(uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	UpdateBroadcastKey(sk_len, sk, ske_len, ske, skp_len, skp, overwrite);
}

void SendSupermanDiscoveryRequest(uint32_t sk_len, unsigned char* sk)
{
	SendDiscoveryRequestPacket(sk_len, sk);
}

void SendSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	SendCertificateRequestPacket(address, sk_len, sk);
}

void SendSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	// SendSupermanCertificateExchangePacket(address, certificate_len, certificate);	
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	uint32_t bkey_len;
	unsigned char* bkey;

	// Get a reference to the actual key, no need for a copy.
	if(GetBroadcastKey(&bkey_len, &bkey))
	{
		// SendCertificateExchangeWithBroadcastKeyPacket(address, certificate_len, certificate, bkey_len, bkey);	
	} 
}

void SendSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	// SendBroadcastKeyExchangePacket(broadcast_key_len, broadcast_key);
}

void SendSupermanSKInvalidate(uint32_t address)
{
	// SendSKInvalidatePacket(address);
}

#else

#include "security.h"

void ReceivedSupermanDiscoveryRequest(uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp, int32_t ifindex)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	printf("Processor: \tObtaining SKE and SKP from the SK (sk_len: %u, sk: %u)...\n", sk_len, (uint32_t)((void*)sk));
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		printf("Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(address, 1, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);

		uint32_t our_sk_len;
		unsigned char* our_sk;
		printf("Processor: \tGrabbing our SK...\n");
		if(MallocAndCopyPublickey(&our_sk_len, &our_sk))
		{
			printf("Processor: \tRequesting to send a certificate request...\n");
			SendSupermanCertificateRequest(address, our_sk_len, our_sk);
			free(our_sk);
		}

		free(ske);
		free(skp);
	}
	else
	{
		printf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
	}
}

void ReceivedSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp, int32_t ifindex)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanSecurityTableEntry(address, 2, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);
		free(ske);
		free(skp);
		
		uint32_t our_cert_len;;
		unsigned char* our_cert;
		if(MallocAndCopyCertificate(&our_cert_len, &our_cert))
		{
			SendSupermanCertificateExchange(address, our_cert_len, our_cert);
			free(our_cert);
		}
	}
}

void ReceivedSupermanCertificateExchange(uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate)
{
	if(VerifyCertificate(certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp, -1, -1);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;
			
			uint32_t our_cert_len;;
			unsigned char* our_cert;
			if(MallocAndCopyCertificate(&our_cert_len, &our_cert))
			{

				// In userspace, we don't know if the kernel has a broadcast key.
				//if(!HasBroadcastKey())
				{
					uint32_t bk_len;
					unsigned char* bk;

					if(MallocAndGenerateNewKey(&bk_len, &bk))
					{
						if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
						{
							UpdateSupermanBroadcastKey(bk_len, bk, ske_len, ske, skp_len, skp, false);
							free(ske);
							ske = NULL;
							free(skp);
							skp = NULL;
						}
						free(bk);
						bk = NULL;			
					}
				}

				// Send the certificate exchange with the broadcast key. The broadcast key is in kernel memory.
				SendSupermanCertificateExchangeWithBroadcastKey(address, our_cert_len, our_cert);

				free(our_cert);
			}

		}
	}
	else
	{
		UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "", -1, -1);
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	if(VerifyCertificate(certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp, -1, -1);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
			{			
				// This has to be done before we commit the new key.
				SendSupermanBroadcastKeyExchange(broadcast_key_len, broadcast_key);
			
				UpdateSupermanBroadcastKey(broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);
				free(ske);
				ske = NULL;
				free(skp);
				skp = NULL;
			}
		}
	}
	else
	{
		UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "", -1, -1);
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp, -1, -1);
		free(ske);
		free(skp);
	}
}

void ReceivedSupermanSKInvalidate(uint32_t address)
{
	UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "", -1, -1);
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
	{			
		UpdateSupermanBroadcastKey(broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);
		free(ske);
		ske = NULL;
		free(skp);
		skp = NULL;
	}
}

#endif
