#include "superman.h"
#include "processor.h"
#include "netlink.h"
#include "security_table.h"

#ifdef __KERNEL__

#include "interfaces_table.h"
#include "packet.h"
#include "security.h"
#include "queue.h"

void LoadNodeCertificateAndSecureInterface(uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename, uint32_t interface_name_len, unsigned char* interface_name)
{
	//printk(KERN_INFO "SUPERMAN: LoadNodeCertificateAndSecureInterface...\n");

	struct net *net = GetNet();
	if(net)
	{
		struct net_device* dev;
		uint32_t ifindex;

		//printk(KERN_INFO "SUPERMAN: LoadNodeCertificateAndSecureInterface triggered.\n");

		dev = dev_get_by_name(net, interface_name);
		if(dev) 
		{
			ifindex = dev->ifindex;
			LoadNodeCertificateThenSecureInterface(ifindex, node_cert_filename_len, node_cert_filename, node_privatekey_filename_len, node_privatekey_filename);

			dev_put(dev);
		}
		else
			printk(KERN_INFO "SUPERMAN: LoadNodeCertificateAndSecureInterface - dev is NULL for %s.\n", interface_name);

		put_net(net);
	}
	else
		printk(KERN_INFO "SUPERMAN: GetNet returned NULL.\n");
}

void SecureInterface(uint32_t ifindex)
{
	//printk(KERN_INFO "SUPERMAN: SecureInterface - Adding to the interfaces table.\n");
	if(!AddInterfacesTableEntry(ifindex))
		printk(KERN_INFO "SUPERMAN: SecureInterface - failed to add interface %d.\n", ifindex);
	else if(!HasBroadcastKey(ifindex))
	{
		//printk(KERN_INFO "SUPERMAN: SecureInterface - Requesting new broadcast key.\n");
		RaiseNewBroadcastKey(ifindex);
	}
}

void SecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	if(interface_name_len > 0)
	{
		//printk(KERN_INFO "SUPERMAN: Adding %s to the interfaces table.\n", interface_name);
		uint32_t ifindex = GetInterfaceFromName(interface_name);
		if(ifindex == -1)
			printk(KERN_INFO "SUPERMAN: SecureInterface - failed to get interface index for %s.\n", interface_name);
		else
			SecureInterface(ifindex);
	}
}

void UnsecureInterface(uint32_t ifindex)
{
	//printk(KERN_INFO "SUPERMAN: Removing from the interfaces table.\n");
	if(!RemoveInterfacesTableEntry(ifindex))
		printk(KERN_INFO "SUPERMAN: UnsecureInterface - failed to remove interface %d.\n", ifindex);
}

void UnsecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	if(interface_name_len > 0)
	{
		//printk(KERN_INFO "SUPERMAN: Removing %s from the interfaces table.\n", interface_name);

		uint32_t ifindex = GetInterfaceFromName(interface_name);
		if(ifindex == -1)
			printk(KERN_INFO "SUPERMAN: SecureInterface - failed to get interface index for %s.\n", interface_name);
		else
			UnsecureInterface(ifindex);
	}
}

// void UpdateSupermanInterfaceTableEntry(uint32_t interface_name_len, unsigned char* interface_name, bool monitor_flag)
// {
// 	if(monitor_flag)
// 	{
// 		printk(KERN_INFO "SUPERMAN: Adding %s to the interfaces table.\n", interface_name);
// 		AddInterfacesTableEntryByName(interface_name);
// 	}
// 	else
// 	{
// 		printk(KERN_INFO "SUPERMAN: Removing %s from the interfaces table.\n", interface_name);
// 		RemoveInterfacesTableEntryByName(interface_name);
// 	}
// }

void UnloadAll()
{
	UnloadSupermanNet();
}

void UpdateSupermanSecurityTableEntry(uint32_t ifindex, uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	if(!UpdateOrAddSecurityTableEntry(ifindex, address, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp))
		printk(KERN_INFO "SUPERMAN: UpdateSupermanSecurityTableEntry - failed to update or add security table entry for ifindex %d.\n", ifindex);
	else
	{
		// Any packets waiting in the queue to be sent can go now.
		if(flag == SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
			SetVerdict(SUPERMAN_QUEUE_SEND, ifindex, address);
	}
}

void UpdateSupermanBroadcastKey(uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	if(!UpdateBroadcastKey(ifindex, sk_len, sk, ske_len, ske, skp_len, skp, overwrite))
		printk(KERN_INFO "SUPERMAN: UpdateSupermanBroadcastKey - failed to update broadcast key for ifindex %d.\n", ifindex);
}

void TriggerSupermanDiscoveryRequest(void)
{
	struct net_device *dev;

	INTERFACE_ITERATOR_START(dev)
	RaiseSupermanDiscoveryRequest(dev->ifindex);
	INTERFACE_ITERATOR_END
}

void SendSupermanDiscoveryRequest(uint32_t ifindex, uint32_t sk_len, unsigned char* sk)
{
	SendDiscoveryRequestPacket(ifindex, sk_len, sk);
}

void SendSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	SendCertificateRequestPacket(ifindex, address, sk_len, sk);
}

void SendSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	SendCertificateExchangePacket(ifindex, address, certificate_len, certificate);
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	uint32_t bkey_len;
	unsigned char* bkey;

	// Get a reference to the actual key, no need for a copy.
	if(GetBroadcastKey(ifindex, &bkey_len, &bkey))
	{
		SendCertificateExchangeWithBroadcastKeyPacket(ifindex, address, certificate_len, certificate, bkey_len, bkey);
	}
}

void SendSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key, bool only_if_changed)
{
	struct security_table_entry* entry;
	bool send = true;

	// We can only do this if we already have a broadcast key
	if(GetSecurityTableEntry(ifindex, INADDR_BROADCAST, &entry) && entry->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
	{
		if(only_if_changed)
		{
			if(entry->sk_len == broadcast_key_len && memcmp(entry->sk, broadcast_key, broadcast_key_len) == 0)
				send = false;
		}

		if(send)
			SendBroadcastKeyExchange(ifindex, broadcast_key_len, broadcast_key);
	}
}

void SendSupermanSKInvalidate(uint32_t ifindex, uint32_t address)
{
	SendSKInvalidatePacket(ifindex, address);
}

#else

#include "security.h"

void LoadNodeCertificateThenSecureInterface(uint32_t ifindex, uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_privatekey_filename_len, unsigned char* node_privatekey_filename)
{
	lprintf(LOG_LEVEL_DEBUG, "Processor: \tStarting LoadNodeCertificateThenSecureInterface.\n");
	// Try and load the certificate. If it loads, we request to secure the interface.
	lprintf(LOG_LEVEL_DEBUG, "Processor: \tCalling LoadNodeCertificates...\n");
	if(LoadNodeCertificates(ifindex, node_cert_filename, node_privatekey_filename))
	{
		// Request to secure the interface
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tCalling SecureInterface...\n");
		SecureInterface(ifindex);
	}
	lprintf(LOG_LEVEL_DEBUG, "Processor: \tFinished LoadNodeCertificateThenSecureInterface.\n");
}

void RaiseSupermanDiscoveryRequest(uint32_t ifindex)
{
	uint32_t sk_len;
	unsigned char* sk;
	if(MallocAndCopyPublickey(ifindex, &sk_len, &sk))
	{
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tCalling SendSupermanDiscoveryRequest...\n");
		DumpKey(LOG_LEVEL_DEBUG, "Processor", "pub ", sk_len, sk);
		SendSupermanDiscoveryRequest(ifindex, sk_len, sk);

		free(sk);
	}
}

void RaiseNewBroadcastKey(uint32_t ifindex)
{
	// In userspace, we don't know if the kernel has a broadcast key.
	uint32_t bk_len;
	unsigned char* bk;
	lprintf(LOG_LEVEL_DEBUG, "Processor: \tGenerating a new broadcast key...\n");
	if(MallocAndGenerateNewKey(&bk_len, &bk))
	{
		DumpKey(LOG_LEVEL_DEBUG, "Processor", "bk  ", bk_len, bk);

		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		lprintf(LOG_LEVEL_DEBUG, "Processor: \tGenerating SKE and SKP for the new broadcast key...\n");
		if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
		{
			lprintf(LOG_LEVEL_DEBUG, "Processor: \tUpdating the new broadcast key...\n");
			DumpKeys(LOG_LEVEL_DEBUG, "Processor", bk_len, bk, ske_len, ske, skp_len, skp);
			UpdateSupermanBroadcastKey(ifindex, bk_len, bk, ske_len, ske, skp_len, skp, false);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;
		}
		else
			lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the new broadcast key.\n");
		free(bk);
		bk = NULL;
	}
}

void ReceivedSupermanDiscoveryRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	lprintf(LOG_LEVEL_DEBUG, "Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndGenerateSharedkeysFromInterface(ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		DumpKeys(LOG_LEVEL_DEBUG, "Processor", sk_len, sk, ske_len, ske, skp_len, skp);

		lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);

		uint32_t our_sk_len;
		unsigned char* our_sk;
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tGrabbing our SK...\n");
		if(MallocAndCopyPublickey(ifindex, &our_sk_len, &our_sk))
		{
			DumpKey(LOG_LEVEL_DEBUG, "Processor", "pub ", our_sk_len, our_sk);

			lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting to send a certificate request...\n");
			SendSupermanCertificateRequest(ifindex, address, our_sk_len, our_sk);
			free(our_sk);
		}
		else
			lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to obtain our SK.\n");

		free(ske);
		free(skp);
	}
	else
		lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateRequest(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	lprintf(LOG_LEVEL_DEBUG, "Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndGenerateSharedkeysFromInterface(ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		DumpKeys(LOG_LEVEL_DEBUG, "Processor", sk_len, sk, ske_len, ske, skp_len, skp);
		
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);
		free(ske);
		free(skp);

		uint32_t our_cert_len;
		unsigned char* our_cert;
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tGrabbing our certificate...\n");
		if(MallocAndCopyCertificate(ifindex, &our_cert_len, &our_cert))
		{
			lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting to send a certificate exchange...\n");
			SendSupermanCertificateExchange(ifindex, address, our_cert_len, our_cert);
			free(our_cert);
		}
		else
			lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to obtain our certificate.\n");
	}
	else
		lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateExchange(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate)
{
	DumpKey(LOG_LEVEL_DEBUG, "Processor", "peer pub", sk_len, sk);

	lprintf(LOG_LEVEL_DEBUG, "Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(ifindex, certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		lprintf(LOG_LEVEL_DEBUG, "Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndGenerateSharedkeysFromInterface(ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			DumpKeys(LOG_LEVEL_DEBUG, "Processor", sk_len, sk, ske_len, ske, skp_len, skp);

			lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			uint32_t our_cert_len;;
			unsigned char* our_cert;
			lprintf(LOG_LEVEL_DEBUG, "Processor: \tGrabbing our certificate...\n");
			if(MallocAndCopyCertificate(ifindex, &our_cert_len, &our_cert))
			{

				/*
				// In userspace, we don't know if the kernel has a broadcast key.

				uint32_t bk_len;
				unsigned char* bk;

				lprintf(LOG_LEVEL_DEBUG, "Processor: \tGenerating a new broadcast key (just in case the kernel doesn't have one yet)...\n");
				if(MallocAndGenerateNewKey(&bk_len, &bk))
				{
					lprintf(LOG_LEVEL_DEBUG, "Processor: \tGenerating SKE and SKP for the new broadcast key (again, just in case)...\n");
					if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
					{
						lprintf(LOG_LEVEL_DEBUG, "Processor: \tUpdating the new broadcast key (again, just in case)...\n");
						UpdateSupermanBroadcastKey(bk_len, bk, ske_len, ske, skp_len, skp, false);
						free(ske);
						ske = NULL;
						free(skp);
						skp = NULL;
					}
					else
						lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the new broadcast key.\n");

					free(bk);
					bk = NULL;
				}
				else
					lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate a new broadcast key.\n");
				*/

				// Send the certificate exchange with the broadcast key. The broadcast key is in kernel memory.
				lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting to send a certificate exchange with broadcast key...\n");
				SendSupermanCertificateExchangeWithBroadcastKey(ifindex, address, our_cert_len, our_cert);

				free(our_cert);
			}
			else
				lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to obtain our certificate..\n");
		}
		else
		{
			lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
		}
	}
	else
	{
		lprintf(LOG_LEVEL_ERROR, "Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	lprintf(LOG_LEVEL_DEBUG, "Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(ifindex, certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		lprintf(LOG_LEVEL_DEBUG, "Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndGenerateSharedkeysFromInterface(ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			DumpKeys(LOG_LEVEL_DEBUG, "Processor", sk_len, sk, ske_len, ske, skp_len, skp);

			lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1);

			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			lprintf(LOG_LEVEL_DEBUG, "Processor: \tGenerating SKE and SKP for the broadcast key...\n");
			if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
			{
				DumpKeys(LOG_LEVEL_DEBUG, "Processor", broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp);

				// This has to be done before we commit the new key.
				lprintf(LOG_LEVEL_DEBUG, "Processor: \tRequesting a broadcast key update for nodes we're associated with...\n");

				SendSupermanBroadcastKeyExchange(ifindex, broadcast_key_len, broadcast_key, true);

				UpdateSupermanBroadcastKey(ifindex, broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);

				free(ske);
				ske = NULL;
				free(skp);
				skp = NULL;
			}
			else
				lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the broadcast key.\n");
		}
		else
		{
			lprintf(LOG_LEVEL_ERROR, "Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
		}
	}
	else
	{
		lprintf(LOG_LEVEL_ERROR, "Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndGenerateSharedkeysFromInterface(ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		lprintf(LOG_LEVEL_DEBUG, "Processor: SK Response - Keys for %u.%u.%u.%u:\n", 0x0ff & address, 0x0ff & (address >> 8), 0x0ff & (address >> 16), 0x0ff & (address >> 24));
		DumpKeys(LOG_LEVEL_DEBUG, "Processor", sk_len, sk, ske_len, ske, skp_len, skp);

		UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);
		free(ske);
		free(skp);
	}
}

void ReceivedSupermanSKInvalidate(uint32_t ifindex, uint32_t address)
{
	UpdateSupermanSecurityTableEntry(ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
	{
		DumpKeys(LOG_LEVEL_DEBUG, "Processor", broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp);

		UpdateSupermanBroadcastKey(ifindex, broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);
		free(ske);
		ske = NULL;
		free(skp);
		skp = NULL;
	}
}

#endif
