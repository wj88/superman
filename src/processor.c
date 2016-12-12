#include "superman.h"
#include "processor.h"
#include "netlink.h"
#include "security_table.h"

#ifdef __KERNEL__

#include "interfaces_table.h"
#include "packet.h"
#include "security.h"
#include "queue.h"

void UpdateSupermanInterfaceTableEntry(uint32_t interface_name_len, unsigned char* interface_name, bool monitor_flag)
{
	if(monitor_flag)
	{
		printk(KERN_INFO "SUPERMAN: Adding %s to the interfaces table.\n", interface_name);
		AddInterfacesTableEntryByName(interface_name);
	}
	else
	{
		printk(KERN_INFO "SUPERMAN: Removing %s from the interfaces table.\n", interface_name);
		RemoveInterfacesTableEntryByName(interface_name);
	}
}

void UnloadAll()
{
	FlushInterfacesTable();
	FlushQueue();
	FlushSecurityTable();
}

void UpdateSupermanSecurityTableEntry(uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp, int32_t ifindex)
{
	UpdateOrAddSecurityTableEntry(address, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);

	// Any packets waiting in the queue to be sent can go now.
	if(flag == SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
		SetVerdict(SUPERMAN_QUEUE_SEND, address);
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
	SendCertificateExchangePacket(address, certificate_len, certificate);
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	uint32_t bkey_len;
	unsigned char* bkey;

	// Get a reference to the actual key, no need for a copy.
	if(GetBroadcastKey(&bkey_len, &bkey))
	{
		SendCertificateExchangeWithBroadcastKeyPacket(address, certificate_len, certificate, bkey_len, bkey);
	}
}

void SendSupermanBroadcastKeyExchange(uint32_t broadcast_key_len, unsigned char* broadcast_key, bool only_if_changed)
{
	struct security_table_entry* entry;
	bool send = true;

	// We can only do this if we already have a broadcast key
	if(GetSecurityTableEntry(INADDR_BROADCAST, &entry) && entry->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
	{
		if(only_if_changed)
		{
			if(entry->sk_len == broadcast_key_len && memcmp(entry->sk, broadcast_key, broadcast_key_len) == 0)
				send = false;
		}

		if(send)
			SendBroadcastKeyExchange(broadcast_key_len, broadcast_key);
	}
}

void SendSupermanSKInvalidate(uint32_t address)
{
	SendSupermanSKInvalidate(address);
}

#else

#include "security.h"

void ReceivedSupermanDiscoveryRequest(uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp, int32_t ifindex)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		// lprintf("Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);

		uint32_t our_sk_len;
		unsigned char* our_sk;
		// lprintf("Processor: \tGrabbing our SK...\n");
		if(MallocAndCopyPublickey(&our_sk_len, &our_sk))
		{
			// lprintf("Processor: \tRequesting to send a certificate request...\n");
			SendSupermanCertificateRequest(address, our_sk_len, our_sk);
			free(our_sk);
		}
		else
			lprintf("Processor: \tFailed to obtain our SK.\n");

		free(ske);
		free(skp);
	}
	else
		lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateRequest(uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp, int32_t ifindex)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		// lprintf("Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);
		free(ske);
		free(skp);

		uint32_t our_cert_len;
		unsigned char* our_cert;
		// lprintf("Processor: \tGrabbing our certificate...\n");
		if(MallocAndCopyCertificate(&our_cert_len, &our_cert))
		{
			// lprintf("Processor: \tRequesting to send a certificate exchange...\n");
			SendSupermanCertificateExchange(address, our_cert_len, our_cert);
			free(our_cert);
		}
		else
			lprintf("Processor: \tFailed to obtain our certificate.\n");
	}
	else
		lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateExchange(uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate)
{
	// lprintf("Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			// lprintf("Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1, -1);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			uint32_t our_cert_len;;
			unsigned char* our_cert;
			// lprintf("Processor: \tGrabbing our certificate...\n");
			if(MallocAndCopyCertificate(&our_cert_len, &our_cert))
			{

				/*
				// In userspace, we don't know if the kernel has a broadcast key.

				uint32_t bk_len;
				unsigned char* bk;

				lprintf("Processor: \tGenerating a new broadcast key (just in case the kernel doesn't have one yet)...\n");
				if(MallocAndGenerateNewKey(&bk_len, &bk))
				{
					lprintf("Processor: \tGenerating SKE and SKP for the new broadcast key (again, just in case)...\n");
					if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
					{
						lprintf("Processor: \tUpdating the new broadcast key (again, just in case)...\n");
						UpdateSupermanBroadcastKey(bk_len, bk, ske_len, ske, skp_len, skp, false);
						free(ske);
						ske = NULL;
						free(skp);
						skp = NULL;
					}
					else
						lprintf("Processor: \tFailed to generate SKE and SKP from the new broadcast key.\n");

					free(bk);
					bk = NULL;
				}
				else
					lprintf("Processor: \tFailed to generate a new broadcast key.\n");
				*/

				// Send the certificate exchange with the broadcast key. The broadcast key is in kernel memory.
				// lprintf("Processor: \tRequesting to send a certificate exchange with broadcast key...\n");
				SendSupermanCertificateExchangeWithBroadcastKey(address, our_cert_len, our_cert);

				free(our_cert);
			}
			else
				lprintf("Processor: \tFailed to obtain our certificate..\n");
		}
		else
		{
			lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1, -1);
		}
	}
	else
	{
		lprintf("Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1, -1);
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	// lprintf("Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			// lprintf("Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1, -1);

			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			// lprintf("Processor: \tGenerating SKE and SKP for the broadcast key...\n");
			if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
			{
				// This has to be done before we commit the new key.
				// lprintf("Processor: \tRequesting a broadcast key update for nodes we're associated with...\n");

				SendSupermanBroadcastKeyExchange(broadcast_key_len, broadcast_key, true);

				UpdateSupermanBroadcastKey(broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);

				free(ske);
				ske = NULL;
				free(skp);
				skp = NULL;
			}
			else
				lprintf("Processor: \tFailed to generate SKE and SKP from the broadcast key.\n");
		}
		else
		{
			lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1, -1);
		}
	}
	else
	{
		lprintf("Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1, -1);
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp, int32_t ifindex)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndDHAndGenerateSharedkeys(sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		//lprintf("Processor: SK Response - Keys for %u.%u.%u.%u:\n", 0x0ff & address, 0x0ff & (address >> 8), 0x0ff & (address >> 16), 0x0ff & (address >> 24));
		//DumpKeys(sk_len, sk, ske_len, ske, skp_len, skp);

		UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp, ifindex);
		free(ske);
		free(skp);
	}
}

void ReceivedSupermanSKInvalidate(uint32_t address)
{
	UpdateSupermanSecurityTableEntry(address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1, -1);
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
