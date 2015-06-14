#include "processor.h"
#include "netlink.h"

#ifdef __KERNEL__

#include "security_table.h"
#include "packet.h"

void UpdateSupermanSecurityTableEntry(uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp)
{
	UpdateOrAddSecurityTableEntry(address, flag, sk_len, sk, ske_len, ske, skp_len, skp);
}

void UpdateSupermanBroadcastKey(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	UpdateBroadcastKey(broadcast_key_len, broadcast_key);
}

void SendSupermanDiscoveryRequest(uint32_t sk_len, unsigned char* sk)
{
	SendDiscoveryRequestPacket(sk_len, sk);
}

void SendSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	// SendSupermanCertificateRequestPacket(sk_len, sk);
}

void SendSupermanCertificateExchange(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	// SendSupermanCertificateExchangePacket(address, certificate_len, certificate);	
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	uint32_t bkey_len;
	unsigned char* bkey;

	if(!HasBroadcastKey())
		if(!UpdateBroadcastKey(broadcast_key_len, broadcast_key))
			return;

	if(MallocAndCopyBroadcastKey(&bkey_len, &bkey))
	{
		// SendSupermanCertificateExchangeWithBroadcastKeyPacket(address, certificate_len, certificate, bkey_len, bkey);	

		kfree(bkey);
	} 
}

void SendSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	// SendSupermanBroadcastKeyExchangePacket(broadcast_key_len, broadcast_key);
}

void SendSupermanSKInvalidate(uint32_t address)
{
	// SendSupermanSKInvalidatePacket(address);
}

#else

#include "security.h"

void ReceivedSupermanDiscoveryRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndCopySharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanSecurityTableEntry(address, 1, sk_len, sk, ske_len, ske, skp_len, skp);

		uint32_t our_sk_len;
		unsigned char* our_sk;
		if(MallocAndCopyPublickey(&our_sk_len, &our_sk))
		{
			SendSupermanCertificateRequest(address, our_sk_len, our_sk);
			free(our_sk);
		}

		free(ske);
		free(skp);
	}
}

void ReceivedSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndCopySharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanSecurityTableEntry(address, 2, sk_len, sk, ske_len, ske, skp_len, skp);
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
	if(VerifyCertificate(certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		if(MallocAndCopySharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp);
			free(ske);
			free(skp);
			
			uint32_t our_cert_len;;
			unsigned char* our_cert;
			if(MallocAndCopyCertificate(&our_cert_len, &our_cert))
			{
				uint32_t bk_len;
				unsigned char* bk;
				if(MallocAndCopyNewKey(&bk_len, &bk))
				{				
					SendSupermanCertificateExchangeWithBroadcastKey(address, our_cert_len, our_cert, bk_len, bk);
					free(bk);
				}

				free(our_cert);
			}

		}
	}
	else
	{
		UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "");
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	if(VerifyCertificate(certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		if(MallocAndCopySharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp);
			free(ske);
			free(skp);

			SendSupermanBroadcastKeyExchange(broadcast_key_len, broadcast_key);
			
			UpdateSupermanBroadcastKey(broadcast_key_len, broadcast_key);
		}
	}
	else
	{
		UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "");
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndCopySharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanSecurityTableEntry(address, 3, sk_len, sk, ske_len, ske, skp_len, skp);
		free(ske);
		free(skp);
	}
}

void ReceivedSupermanSKInvalidate(uint32_t address)
{
	UpdateSupermanSecurityTableEntry(address, 0, 0, "", 0, "", 0, "");
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	UpdateSupermanBroadcastKey(broadcast_key_len, broadcast_key);
}

#endif
