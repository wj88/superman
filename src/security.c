#ifdef __KERNEL__

// Parts of this code have been shamelessly borrowed from the linux/net/ipv4/esp4.c implementation.

#include <linux/netdevice.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/scatterwalk.h>
#include <net/ip.h>

#include "packet.h"
#include "security.h"

// Define our prototypes to prevent kernel build warnings
unsigned int AddE2ESecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err);
unsigned int RemoveE2ESecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err);
unsigned int AddP2PSecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err);
unsigned int RemoveP2PSecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err);
void addP2PSecurityDone(void *data, int err);
void removeP2PSecurityDone(void *data, int err);


static struct crypto_aead* aead = NULL;
static struct crypto_ahash* ahash = NULL;

static struct superman_packet_callback_arg* alloc_tmp_e2e(struct superman_packet_info* spi, struct crypto_aead *aead, int nfrags, int seqhilen)
{
	unsigned int len;
	len = seqhilen;
	len += crypto_aead_ivsize(aead);
	if (len) {
		len += crypto_aead_alignmask(aead) & ~(crypto_tfm_ctx_alignment() - 1);
		len = ALIGN(len, crypto_tfm_ctx_alignment());
	}
	len += sizeof(struct aead_request) + crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += sizeof(struct scatterlist) * nfrags;

	spi->tmp = kmalloc(len, GFP_ATOMIC);
	if(spi->tmp)
		memset(spi->tmp, 0, len);
	return (spi->tmp);
}

static bool alloc_tmp_p2p(struct superman_packet_info* spi, struct crypto_ahash* ahash, int nfrags)
{
	unsigned int len;
	len = crypto_ahash_digestsize(ahash);
	len += sizeof(struct scatterlist) * nfrags;

	spi->tmp = kmalloc(len, GFP_ATOMIC);
	if(spi->tmp)
		memset(spi->tmp, 0, len);
	return (spi->tmp);
}

static inline __be32 *tmp_seqhi(void *tmp)
{
	return PTR_ALIGN((__be32 *)tmp, __alignof__(__be32));
}

static inline u8 *tmp_iv(struct crypto_aead *aead, void *tmp, int seqhilen)
{
	return crypto_aead_ivsize(aead) ? PTR_ALIGN((u8 *)tmp + seqhilen, crypto_aead_alignmask(aead) + 1) : tmp + seqhilen;
}

static inline struct aead_request *tmp_req(struct crypto_aead *aead, u8 *iv)
{
	struct aead_request *req;
	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead), crypto_tfm_ctx_alignment());
	aead_request_set_tfm(req, aead);
	return req;
}

static inline struct scatterlist *req_sg(struct crypto_aead *aead, struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) + crypto_aead_reqsize(aead), __alignof__(struct scatterlist));
}

void dump_packet(struct sk_buff* skb)
{
	int nfrags;
	struct scatterlist *sg;
	struct scatter_walk walk;
	struct sk_buff* trailer;
	unsigned int len;
	unsigned int n;
	unsigned int t = 0;
	unsigned char* data;
	unsigned char buff[56];
	unsigned char abuff[17];
	unsigned int i;

	nfrags = skb_cow_data(skb, 0, &trailer);
	if(nfrags < 0)
		return;

	sg = kmalloc(sizeof(struct scatterlist) * nfrags, GFP_ATOMIC);
	if(!sg)
	{
		printk(KERN_INFO "SUPERMAN security: Failed to allocate memory for a scatterlist\n");
		return;
	}

	if(skb_to_sgvec(skb, sg, 0, skb->len) < 0)
	{
		printk(KERN_INFO "SUPERMAN security: Failed to convert skb to scatterlist\n");
		kfree(sg);
		return;
	}

	len = skb->len;

	scatterwalk_start(&walk, sg);

	while (len) {
		n = scatterwalk_clamp(&walk, len);
		if (!n) {
			scatterwalk_start(&walk, sg_next(walk.sg));
			n = scatterwalk_clamp(&walk, len);
		}
		data = scatterwalk_map(&walk);

		for(i = 0; i < n; i++)
		{
			if(t == 0)
			{
				sprintf(buff, "0000 -");
				abuff[0] = '\0';
			}
			else if(t % 16 == 0)
			{
				printk(KERN_INFO "%-55s   %s\n", buff, abuff);
				sprintf(buff, "%04x -", t);
				abuff[0] = '\0';
			}

			sprintf(buff, "%s %02x", buff, data[i]);
			sprintf(abuff, "%s%c", abuff, ((data[i] >= ' ') && (data[i] <= '~')) ? data[i] : '.');
			t++;
		}
		len -= n;

		scatterwalk_unmap(data);
		scatterwalk_advance(&walk, n);
		scatterwalk_done(&walk, 0, len);
	}
	printk(KERN_INFO "%-55s   %s\n", buff, abuff);

	kfree(sg);
}

void dump_bytes(void* d, int len)
{
	unsigned int i;
	unsigned int t = 0;
	unsigned char* data = (unsigned char*)d;
	unsigned char buff[56];
	unsigned char abuff[17];

	while (len) {
		unsigned int n = len;
		for(i = 0; i < n; i++)
		{
			if(t == 0)
			{
				sprintf(buff, "0000 -");
				abuff[0] = '\0';
			}
			else if(t % 16 == 0)
			{
				printk(KERN_INFO "%-55s   %s\n", buff, abuff);
				sprintf(buff, "%04x -", t);
				abuff[0] = '\0';
			}

			sprintf(buff, "%s %02x", buff, data[i]);
			sprintf(abuff, "%s%c", abuff, ((data[i] >= ' ') && (data[i] <= '~')) ? data[i] : '.');
			t++;
		}
		len -= n;
	}
	printk(KERN_INFO "%-55s   %s\n", buff, abuff);
}

unsigned int AddE2ESecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err)
{
	bool result = false;
	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurityDone)...\n");

	if(err == 0)
	{
		// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurityDone) - Crypto completed successfully.");


		// Discussed this with Andrew - we cannot trim the excess bytes and need to leave in the full block.

		//printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurityDone) - Packet length after security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
		//printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurityDone) - Packet contents:\n");
		//dump_packet(spi->skb);

		// Put the cached ttl back in the IP header
		spi->iph->ttl = spi->ttl;

		ip_send_check(spi->iph);
		result = true;
	}
	else
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurityDone) - Crypto failed.\n");

	if(spi->tmp != NULL)
	{
		kfree(spi->tmp);
		spi->tmp = NULL;
	}

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

static void addE2ESecurityDone(void *data, int err)
{
	struct superman_packet_info* spi = data;
	unsigned int (*callback)(struct superman_packet_info*, bool) = spi->arg;
	// printk(KERN_INFO "SUPERMAN: Security (addE2ESecurityDone)...\n");
	spi->arg = NULL;
	AddE2ESecurityDone(spi, callback, err);
}

unsigned int AddE2ESecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool))
{
	int err;
	int i;
	unsigned int blksize;
	unsigned int aligned_payload_len;
	unsigned int padding_len;
	unsigned int assoc_len;
	unsigned int auth_len;
	unsigned int iv_len;
	int nfrags;
	u8 *iv;
	__be32 *seqhi;
	int seqhilen;
	struct sk_buff* trailer;
	uint8_t* tail;
	struct scatterlist *sg;
	struct aead_request *req;

	//printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Adding E2E security using %s key...\n", (spi->e2e_use_broadcast_key ? "broadcast" : "destinations"));
	//dump_bytes(spi->e2e_security_details->ske, spi->e2e_security_details->ske_len);

	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Packet length before security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Packet contents:\n");
	//dump_packet(spi->skb);

	// If we don't need to secure this packet, accept it.
	if(!spi->e2e_secure_packet)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Not a secured packet.\n");
		spi->result = NF_ACCEPT;
		return callback(spi, true);
	}

	// If we don't have the security details.
	if(!spi->e2e_has_security_details)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - We don't have their security details.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Cache the ttl
	spi->ttl = spi->iph->ttl;
	spi->iph->ttl = 0;

	// Reset the last_addr
	//printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Zeroing last_addr.\n");
	spi->shdr->last_addr = htonl(0);

	// Start with a zero checksum.
	spi->iph->check = 0;

	// We have a key to use, load it into the crypto process.
	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Key:\n");
	// dump_bytes(spi->security_details->ske, spi->security_details->ske_len);
	err = crypto_aead_setkey(aead, spi->e2e_security_details->ske, spi->e2e_security_details->ske_len);
	if(err < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Failed to set the security key");
		// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Key len: %u, Key %u, err: %d, flags: %x.\n", spi->e2e_security_details->ske_len, (uint32_t)(spi->e2e_security_details->ske), err, crypto_aead_get_flags(aead));
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	//printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Key len: %u, Key %u, err: %d, flags: %x.\n", spi->e2e_security_details->ske_len, *(uint32_t*)(spi->e2e_security_details->ske), err, crypto_aead_get_flags(aead));

	// Auth bytes len
	auth_len = crypto_aead_authsize(aead);

	// IV bytes len
	iv_len = crypto_aead_ivsize(aead);

	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Requested auth len: %u, Actual auth len: %u, IV len: %u\n", MAC_LEN, auth_len, iv_len);

	// Size of a single block
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);

	// The bloated payload (payload rounded up to the nearest block size)
	aligned_payload_len = ALIGN(ntohs(spi->shdr->payload_len), blksize);

	// Size of the padding added to make contents up to block size
	padding_len = aligned_payload_len - ntohs(spi->shdr->payload_len);

	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Block size: %u, Payload len: %u, Aligned Payload len: %u, Padding len: %u, Num blocks: %u\n", blksize, ntohs(spi->shdr->payload_len), aligned_payload_len, padding_len, aligned_payload_len / blksize);

	// Size of the associated data
	assoc_len = sizeof(struct iphdr) + sizeof(struct superman_header);

	// Grab the scatterlist length whilst ensuring we have space for the currently not added data padding data.
	nfrags = skb_cow_data(spi->skb, padding_len + auth_len, &trailer);
	if(nfrags < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - skb_cow_data failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Increment the IP header to match the increase in packet size.
	spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) + padding_len + auth_len);

	// Reserve the space in the skb for our padding to fill the block size.
	tail = pskb_put(spi->skb, trailer, padding_len + auth_len);

	// Make sure the buffer is linear or direct manipulation will likely fail.
	// skb_linearize(spi->skb);

	// Fill the padding with known data.
	for (i = 0; i < padding_len; i++)
		tail[i] = i + 1;

	// Clear the auth bytes
	for (i = padding_len; i < padding_len + MAC_LEN; i++)
		tail[i] = 0;

	// No longer checksumed
	// spi->skb->ip_summed = CHECKSUM_NONE;

	// We need some temporary memory to store stuff. Allocate the memory then divide it up.
	seqhilen = 0;

	// Allocate some memory attached to spi->tmp to host the scatter list.
	if(!alloc_tmp_e2e(spi, aead, nfrags, seqhilen))
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - alloc_tmp_e2e failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}
	seqhi = tmp_seqhi(spi->tmp);
	iv = tmp_iv(aead, spi->tmp, seqhilen);
	req = tmp_req(aead, iv);
	sg = req_sg(aead, req);

	// Initialise the contents scatterlist with the number of fragments we have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, offset from where the real payload data.
	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Encrypting %u bytes at offset %lu bytes with %u bytes of associated data...\n", aligned_payload_len, skb_transport_offset(spi->skb) + sizeof(struct superman_header), assoc_len);

	if(skb_to_sgvec(spi->skb, sg, skb_network_offset(spi->skb), assoc_len + aligned_payload_len + auth_len) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Failed to convert skb to scatterlist\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Setup aead
	aead_request_set_callback(req, 0, addE2ESecurityDone, spi);
	aead_request_set_crypt(req, sg, sg, aligned_payload_len, iv);
	aead_request_set_ad(req, assoc_len);

	// Pop the callback into the spi.
	spi->arg = callback;

	// Attempt to perform the encrypt process.
	// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Calling crypto_aead_encrypt...\n");
	err = crypto_aead_encrypt(req);

	// If we're told it's in progress, it is being performed asyncronously... steal the packet.
	if (err == -EINPROGRESS)
	{
		// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Crypto is running asyncronously, stealing packet...\n");
		spi->result = NF_STOLEN;
	}
	// Crypto finished immediately, go straight to the end.
	else
	{
		// printk(KERN_INFO "SUPERMAN: Security (AddE2ESecurity) - Crypto is running syncronously...\n");
		spi->arg = NULL;
		spi->result = AddE2ESecurityDone(spi, callback, err);
	}

	return spi->result;
}

unsigned int RemoveE2ESecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err)
{
	bool result = false;
	int blksize;
	int aligned_payload_len;

	if(err == 0)
	{
		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - Crypto completed successfully.");

		// Size of a single block
		blksize = ALIGN(crypto_aead_blocksize(aead), 4);

		// The bloated payload (payload rounded up to the nearest block size)
		aligned_payload_len = ALIGN(ntohs(spi->shdr->payload_len), blksize);

		// Reduce the IP header size.
		spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) - (aligned_payload_len - ntohs(spi->shdr->payload_len)) - MAC_LEN);

		// Trim the excess off the end, leaving the unencrypted payload and headers.
		pskb_trim(spi->skb, spi->skb->len - (aligned_payload_len - ntohs(spi->shdr->payload_len)) - MAC_LEN);

		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - Packet length after security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - Packet contents:\n");
		// dump_packet(spi->skb);

		// Put the cached ttl back in the IP header
		spi->iph->ttl = spi->ttl;

		ip_send_check(spi->iph);
		result = true;
	}
	else
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - Crypto failed. err: %d, flags: %x.\n", err, crypto_aead_get_flags(aead));
		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - Packet contents:\n");
		// dump_packet(spi->skb);
		//printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurityDone) - E2E Key:\n");
		//dump_bytes(spi->e2e_security_details->ske, spi->e2e_security_details->ske_len);
	}

	if(spi->tmp != NULL)
	{
		kfree(spi->tmp);
		spi->tmp = NULL;
	}

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

static void removeE2ESecurityDone(void *data, int err)
{
	struct superman_packet_info* spi = data;
	unsigned int (*callback)(struct superman_packet_info*, bool) = spi->arg;
	spi->arg = NULL;
	RemoveE2ESecurityDone(spi, callback, err);
}

unsigned int RemoveE2ESecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool))
{
	int err;
	unsigned int auth_len;
	unsigned int blksize;
	unsigned int aligned_payload_len;
	unsigned int padding_len;
	unsigned int assoc_len;
	unsigned int iv_len;
	int nfrags;
	u8 *iv;
	__be32 *seqhi;
	int seqhilen;
	struct sk_buff* trailer;
	struct scatterlist *sg;
	struct aead_request *req;

//			Transformation during E2E removal.
//
//	----------------------------------------------------------------------------------
//	| IP Header | SUPERMAN Header | Encrypted Payload		| Padding | Auth |
//	----------------------------------------------------------------------------------
//					|
//					v
//			      ---------------------
//			      | RemoveE2ESecurity |
//			      ---------------------
//					|
//					v
//	----------------------------------------------------------------------------------
//	| IP Header | SUPERMAN Header | Payload				| Padding | Auth |
//	----------------------------------------------------------------------------------
//					|
//					v
//			    -------------------------
//			    | RemoveE2ESecurityDone |
//			    -------------------------
//					|
//					v
//	-----------------------------------------------------------------
//	| IP Header | SUPERMAN Header | Payload				|
//	-----------------------------------------------------------------


	//printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Removing E2E security using %s key...\n", (spi->e2e_use_broadcast_key ? "broadcast" : "destinations"));

	// If we don't need to secure this packet, accept it.
	if(!spi->e2e_secure_packet)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Not a secured packet.\n");
		spi->result = NF_ACCEPT;
		return callback(spi, true);
	}

	// If we don't have the security details.
	if(!spi->e2e_has_security_details)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - We don't have their security details.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Cache the ttl
	spi->ttl = spi->iph->ttl;
	spi->iph->ttl = 0;

	// Reset the last_addr
	//printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Zeroing last_addr.\n");
	spi->shdr->last_addr = htonl(0);

	// Start with a zero checksum.
	spi->iph->check = 0;

	//printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Packet length before security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
	//printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Packet contents:\n");
	//dump_packet(spi->skb);

	// We have a key to use, load it into the crypto process.
	// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Key:\n");
	// dump_bytes(spi->security_details->ske, spi->e2e_security_details->ske_len);
	if(crypto_aead_setkey(aead, spi->e2e_security_details->ske, spi->e2e_security_details->ske_len) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Failed to set the security key.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Auth bytes len
	auth_len = crypto_aead_authsize(aead);

	// IV bytes len
	iv_len = crypto_aead_ivsize(aead);

	// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Requested auth len: %u, Actual auth len: %u, IV len: %u\n", MAC_LEN, auth_len, iv_len);

	// Size of a single block
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);

	// The bloated payload (payload rounded up to the nearest block size)
	aligned_payload_len = ALIGN(ntohs(spi->shdr->payload_len), blksize);

	// Size of the padding added to make contents up to block size
	padding_len = aligned_payload_len - ntohs(spi->shdr->payload_len);

	// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Block size: %u, Payload len: %u, Aligned Payload len: %u, Padding len: %u, Num blocks: %u\n", blksize, ntohs(spi->shdr->payload_len), aligned_payload_len, padding_len, aligned_payload_len / blksize);

	// Size of the associated data
	assoc_len = sizeof(struct iphdr) + sizeof(struct superman_header);

	// Grab the scatterlist length whilst ensuring we have space for the currently not added data padding data.
	nfrags = skb_cow_data(spi->skb, 0, &trailer);
	if(nfrags < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - skb_cow_data failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// We need some temporary memory to store stuff. Allocate the memory then divide it up.
	// sglists = 1;
	seqhilen = 0;

	// Allocate some memory attached to spi->tmp to host the scatter list.
	if(!alloc_tmp_e2e(spi, aead, nfrags, seqhilen))
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - alloc_tmp_e2e failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}
	seqhi = tmp_seqhi(spi->tmp);
	iv = tmp_iv(aead, spi->tmp, seqhilen);
	req = tmp_req(aead, iv);
	sg = req_sg(aead, req);

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, offset from where the real payload data.
	// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Decrypting %u bytes at offset %lu bytes with %u of associated data...\n", aligned_payload_len, skb_transport_offset(spi->skb) + sizeof(struct superman_header), assoc_len);
	if(skb_to_sgvec(spi->skb, sg, skb_network_offset(spi->skb), assoc_len + aligned_payload_len + auth_len) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Failed to convert skb to scatterlist\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Setup aead
	aead_request_set_callback(req, 0, removeE2ESecurityDone, spi);
	aead_request_set_crypt(req, sg, sg, aligned_payload_len + auth_len, iv);
	aead_request_set_ad(req, assoc_len);

	// Pop the callback into the spi.
	spi->arg = callback;

	// Attempt to perform the decrypt process.
	err = crypto_aead_decrypt(req);

	// If we're told it's in progress, it is being performed asyncronously... steal the packet.
	if (err == -EINPROGRESS)
	{
		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Crypto is running asyncronously, stealing packet...\n");
		spi->result = NF_STOLEN;
	}
	// Crypto finished immediately, go straight to the end.
	else
	{
		// printk(KERN_INFO "SUPERMAN: Security (RemoveE2ESecurity) - Crypto is running syncronously...\n");
		spi->arg = NULL;
		spi->result = RemoveE2ESecurityDone(spi, callback, err);
	}

	return spi->result;
}

unsigned int AddP2PSecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err)
{
	bool result = false;

	if(err == 0)
	{
		struct sk_buff* trailer;

		// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurityDone) - Crypto completed successfully.");

		// Make sure there is space for our HMAC to go at the end of the data.
		if(skb_cow_data(spi->skb, HMAC_LEN, &trailer) >= 0)
		{
			// Grab the space for the correct number of bytes.
			unsigned char* tail = pskb_put(spi->skb, trailer, HMAC_LEN);

			// Copy the HMAC into the allocated space.
			memcpy(tail, spi->tmp, HMAC_LEN);

			// Increase the IP header size.
			spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) + HMAC_LEN);

			// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurityDone) - Packet length after security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
			// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurityDone) - Packet contents:\n");
			// dump_packet(spi->skb);

			// Put the cached ttl back in the IP header
			spi->iph->ttl = spi->ttl;

			ip_send_check(spi->iph);
			result = true;
		}
		else
			printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurityDone) - Failed skb_cow_data.\n");
	}
	else
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurityDone) - Crypto failed.\n");

	if(spi->tmp != NULL)
	{
		kfree(spi->tmp);
		spi->tmp = NULL;
	}

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

void addP2PSecurityDone(void *data, int err)
{
	struct superman_packet_info* spi = data;
	unsigned int (*callback)(struct superman_packet_info*, bool) = spi->arg;
	spi->arg = NULL;
	AddP2PSecurityDone(spi, callback, err);
}

unsigned int AddP2PSecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool))
{
	int err;
	unsigned char* hash_buffer;
	int nfrags;
	struct scatterlist *sg;
	struct ahash_request *req;
	struct sk_buff* trailer;

	//printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Adding P2P security using %s key...\n", (spi->p2p_use_broadcast_key ? "broadcast" : "link"));

	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Packet length before security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Packet contents:\n");
	// dump_packet(spi->skb);

	// If we don't need to secure this packet, accept it.
	if(!spi->p2p_secure_packet)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Not a secured packet.\n");
		spi->result = NF_ACCEPT;
		return callback(spi, true);
	}

	// If we don't have the security details.
	if(!spi->p2p_has_security_details)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - We don't have their security details.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Add the our address to the header.
	//printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Setting last_addr to our address.\n");
	spi->shdr->last_addr = spi->p2p_our_addr;

	// We have a key to use, load it into the crypto process.
	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Setting hash key...\n");
	if(crypto_ahash_setkey(ahash, spi->p2p_security_details->skp, spi->p2p_security_details->skp_len) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Failed to set the security key.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Grab the scatterlist length.
	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Calling skb_cow_data...\n");
	nfrags = skb_cow_data(spi->skb, 0, &trailer);
	if(nfrags < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - skb_cow_data failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Allocate some memory attached to spi->tmp to host the resulting hash and the scatter list.
	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Calling alloc_tmp_p2p...\n");
	if(!alloc_tmp_p2p(spi, ahash, nfrags))
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - alloc_tmp_p2p failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Start with a zero checksum.
	spi->iph->check = 0;

	// Cache the ttl
	spi->ttl = spi->iph->ttl;
	spi->iph->ttl = 0;

	// Grab a reference to the hash buffer portion of our memory allocation
	hash_buffer = spi->tmp;

	// Grab a reference to the scatter list portion of our memory allocation
	sg = (spi->tmp + crypto_ahash_digestsize(ahash));

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, from the end of the network header, including everything else.
	// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Hashing %lu bytes...\n", spi->skb->len - sizeof(struct iphdr));
	if(skb_to_sgvec(spi->skb, sg, skb_transport_offset(spi->skb), spi->skb->len - sizeof(struct iphdr)) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Failed to convert skb to scatterlist\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Allocate the request for the hmac
	req = ahash_request_alloc(ahash, GFP_ATOMIC);

	// Setup ahash request callback
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, addP2PSecurityDone, spi);

	// Setup ahash data to perform hashing over
	ahash_request_set_crypt(req, sg, hash_buffer, spi->skb->len - sizeof(struct iphdr));

	// Pop the callback into the spi.
	spi->arg = callback;

	// Attempt to perform the hash process.
	err = crypto_ahash_digest(req);

	// If we're told it's in progress, it is being performed asyncronously... steal the packet.
	if (err == -EINPROGRESS)
	{
		printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Crypto is running asyncronously, stealing packet...\n");
		spi->result = NF_STOLEN;
	}
	// Crypto finished immediately, go straight to the end.
	else
	{
		// printk(KERN_INFO "SUPERMAN: Security (AddP2PSecurity) - Crypto is running syncronously...\n");
		spi->arg = NULL;
		spi->result = AddP2PSecurityDone(spi, callback, err);
	}

	return spi->result;
}

unsigned int RemoveP2PSecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err)
{
	bool result = false;

	if(err == 0)
	{
		int i;
		unsigned char* storedHMAC; // = payload + ntohs(shdr->payload_len) + MAC_LEN;
		unsigned char* calcHMAC = spi->tmp;

		// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Crypto completed successfully.\n");

		storedHMAC = kmalloc(HMAC_LEN, GFP_ATOMIC);
		if(storedHMAC)
		{
			if(skb_copy_bits(spi->skb, spi->skb->len - HMAC_LEN, storedHMAC, HMAC_LEN) == 0)
			{
				result = true;

				for(i = 0; i < HMAC_LEN; i++)
				{
					if(storedHMAC[i] != calcHMAC[i])
					{
						printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - HMAC comparison failed.\n");
						result = false;
						break;
					}
				}

			}
			else
				printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Failed to skb_copy_bits.\n");

			kfree(storedHMAC);
		}
		else
			printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Failed to allocate memory.\n");


		// Trim the hmac off the end.
		pskb_trim(spi->skb, spi->skb->len - HMAC_LEN);
		spi->iph->tot_len = htons(ntohs(spi->iph->tot_len) - HMAC_LEN);

		// Remove the last_addr
		//printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Zeroing last_addr.\n");
		spi->shdr->last_addr = htonl(0);

		// Put the cached ttl back in the IP header
		spi->iph->ttl = spi->ttl;

		// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Packet length after security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
		// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Packet contents:\n");
		// dump_packet(spi->skb);

		ip_send_check(spi->iph);
	}
	else
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurityDone) - Crypto failed.\n");

	if(spi->tmp != NULL)
	{
		kfree(spi->tmp);
		spi->tmp = NULL;
	}

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

void removeP2PSecurityDone(void *data, int err)
{
	struct superman_packet_info* spi = data;
	unsigned int (*callback)(struct superman_packet_info*, bool) = spi->arg;
	spi->arg = NULL;
	AddP2PSecurityDone(spi, callback, err);
}

unsigned int RemoveP2PSecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool))
{
	int err;
	unsigned char* hash_buffer;
	int nfrags;
	struct scatterlist *sg;
	struct ahash_request *req;
	struct sk_buff* trailer;

	//printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Removing P2P security using %s key...\n", (spi->p2p_use_broadcast_key ? "broadcast" : "link"));

	// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Packet length before security: %u, IP Header Total Length: %u\n", spi->skb->len, ntohs(spi->iph->tot_len));
	// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Packet contents:\n");
	// dump_packet(spi->skb);

	// If we don't need to secure this packet, accept it.
	if(!spi->p2p_secure_packet)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Not a secured packet.\n");

		spi->result = NF_ACCEPT;
		return callback(spi, true);
	}

	// If we don't have the security details.
	if(!spi->p2p_has_security_details)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - We don't have their security details.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// We have a key to use, load it into the crypto process.
	if(crypto_ahash_setkey(ahash, spi->p2p_security_details->skp, spi->p2p_security_details->skp_len) != 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Failed to set the security key.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Grab the scatterlist length.
	nfrags = skb_cow_data(spi->skb, 0, &trailer);
	if(nfrags < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - skb_cow_data failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Allocate some memory attached to spi->tmp to host the resulting hash and the scatter list.
	if(!alloc_tmp_p2p(spi, ahash, nfrags))
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - alloc_tmp_p2p failed.\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Start with a zero checksum.
	spi->iph->check = 0;

	// Cache the ttl
	spi->ttl = spi->iph->ttl;
	spi->iph->ttl = 0;

	// Grab a reference to the hash buffer portion of our memory allocation
	hash_buffer = spi->tmp;

	// Grab a reference to the scatter list portion of our memory allocation
	sg = (spi->tmp + crypto_ahash_digestsize(ahash));

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, from the end of the network header, including everything else.
	// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Hashing %lu bytes...\n", spi->skb->len - sizeof(struct iphdr) - HMAC_LEN);
	if(skb_to_sgvec(spi->skb, sg, skb_transport_offset(spi->skb), spi->skb->len - sizeof(struct iphdr) - HMAC_LEN) < 0)
	{
		printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Failed to convert skb to scatterlist\n");
		spi->result = NF_DROP;
		return callback(spi, false);
	}

	// Allocate the request for the hmac
	req = ahash_request_alloc(ahash, GFP_ATOMIC);

	// Setup ahash request callback
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, removeP2PSecurityDone, spi);

	// Setup ahash data to perform hashing over
	ahash_request_set_crypt(req, sg, hash_buffer, spi->skb->len - sizeof(struct iphdr) - HMAC_LEN);

	// Pop the callback into the spi.
	spi->arg = callback;

	// Attempt to perform the hash process.
	err = crypto_ahash_digest(req);

	// If we're told it's in progress, it is being performed asyncronously... steal the packet.
	if (err == -EINPROGRESS)
	{
		// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Crypto is running asyncronously, stealing packet...\n");
		spi->result = NF_STOLEN;
	}
	// Crypto finished immediately, go straight to the end.
	else
	{
		// printk(KERN_INFO "SUPERMAN: Security (RemoveP2PSecurity) - Crypto is running syncronously...\n");
		spi->arg = NULL;
		spi->result = RemoveP2PSecurityDone(spi, callback, err);
	}

	return spi->result;
}

bool InitSecurity(void)
{
	aead = crypto_alloc_aead(AEAD_ALG_NAME, 0, 0);
	if(IS_ERR(aead))
	{
		aead = NULL;
		printk(KERN_ERR "SUPERMAN: Security - Failed to alloc aead.\n");
		return false;
	}

	if(crypto_aead_setauthsize(aead, MAC_LEN) != 0)
	{
		printk(KERN_ERR "SUPERMAN: Security - Failed to set auth size.\n");
		DeInitSecurity();
		return false;
	}

	ahash = crypto_alloc_ahash(HMAC_ALG_NAME, 0, 0);
	if(IS_ERR(aead))
	{
		printk(KERN_ERR "SUPERMAN: Security - Failed to alloc ahash.\n");
		DeInitSecurity();
		return false;
	}

	return true;
}

void DeInitSecurity(void)
{
	if(aead)
	{
		crypto_free_aead(aead);
		aead = NULL;
	}

	if(ahash)
	{
		crypto_free_ahash(ahash);
		ahash = NULL;
	}
}

#else

// To create the authority and requesting certificates:
// https://help.ubuntu.com/lts/serverguide/certificates-and-security.html

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <net/if.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/kdf.h>

#include "security.h"
#include "netlink.h"

bool EVP_PKEY_compare(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char buf_a[64], buf_b[64];  // Supports up to Ed448
    size_t len_a = sizeof(buf_a), len_b = sizeof(buf_b);

    if (EVP_PKEY_get_raw_public_key(a, buf_a, &len_a) != 1 ||
        EVP_PKEY_get_raw_public_key(b, buf_b, &len_b) != 1)
        return false;

    return (len_a == len_b) && (memcmp(buf_a, buf_b, len_a) == 0);
}

struct certificate {
	uint32_t		cert_data_len;
	unsigned char*	cert_data;
	BIO*			cert_bio;
	X509_STORE*		cert_store;
	X509*			cert;
};

struct node {
	uint32_t			ifindex;
	uint32_t			interface_name_len;
	unsigned char*		interface_name;

	struct certificate	certificate;
	uint32_t			privatekey_data_len;
	unsigned char*		privatekey_data;
	BIO*				privatekey_bio;
	EVP_PKEY*			privatekey;
	EVP_PKEY*			publickey;
};


#define NODES_INIT_CAPACITY 4

struct nodes {
	struct node** 		items;
	int					capacity;
	int					total;
};

struct vault {
	struct certificate	certificate_authority;
	struct nodes		nodes;
};

void certificate_init(struct certificate* c)
{
	c->cert				= NULL;
	c->cert_bio			= NULL;
	c->cert_data		= NULL;
	c->cert_data_len	= 0;
	c->cert_store		= NULL;
}

void nodes_init(struct vault *v)
{
	v->nodes.capacity	= NODES_INIT_CAPACITY;
	v->nodes.total		= 0;
	v->nodes.items		= malloc(sizeof(struct node*) * v->nodes.capacity);
}

void node_init(struct node *n, uint32_t ifindex)
{
	certificate_init(&(n->certificate));

	n->ifindex				= ifindex;
	n->interface_name_len	= 0;
	n->interface_name		= NULL;
	n->privatekey_data_len	= 0;
	n->privatekey_data		= NULL;
	n->privatekey_bio		= NULL;
	n->privatekey			= NULL;
	n->publickey			= NULL;
}

struct node* node_create(uint32_t ifindex)
{
	struct node *node = (struct node*)malloc(sizeof(struct node));
	node_init(node, ifindex);
	return node;
}

void certificate_free(struct certificate* c)
{
	if(c->cert_store)
	{
		X509_STORE_free(c->cert_store);
		c->cert_store = NULL;
	}
	if(c->cert)
	{
		X509_free(c->cert);
		c->cert = NULL;
	}
	if(c->cert_bio)
	{
		BIO_free_all(c->cert_bio);
		c->cert_bio = NULL;
	}
	if(c->cert_data)
	{
		free(c->cert_data);
		c->cert_data = NULL;
		c->cert_data_len = 0;
	}
}

void node_free(struct node* node)
{
	certificate_free(&(node->certificate));
	if(node->privatekey_data)
	{
		OPENSSL_free(node->privatekey_data);
		node->privatekey_data = NULL;
		node->privatekey_data_len = 0;
	}
	if(node->privatekey_bio)
	{
		BIO_free_all(node->privatekey_bio);
		node->privatekey_bio = NULL;
	}
	if(node->privatekey)
	{
		EVP_PKEY_free(node->privatekey);
		node->privatekey = NULL;
	}
	if(node->publickey)
	{
		EVP_PKEY_free(node->publickey);
		node->publickey = NULL;
	}
}

void node_delete(struct node* node)
{
	node_free(node);
	free(node);
}

int nodes_total(struct nodes *v)
{
	return v->total;
}

static void nodes_resize(struct vault *v, int capacity)
{
	struct node** items = realloc(v->nodes.items, sizeof(struct node*) * capacity);
	if (items) {
		v->nodes.items = items;
		v->nodes.capacity = capacity;
	}
}

void nodes_add(struct vault *v, struct node *item)
{
	if (v->nodes.capacity == v->nodes.total)
		nodes_resize(v, v->nodes.capacity * 2);
	v->nodes.items[v->nodes.total++] = item;
}

struct node* nodes_get(struct vault *v, int index)
{
	if (index >= 0 && index < v->nodes.total)
		return v->nodes.items[index];
	return NULL;
}

struct node* nodes_find(struct vault *v, uint32_t ifindex)
{
    for (int i = 0; i < v->nodes.total; i++) {
	    if(v->nodes.items[i]->ifindex == ifindex)
	    	return v->nodes.items[i];
    }
    return NULL;
}

bool nodes_exists(struct vault *v, uint32_t ifindex)
{
	return nodes_find(v, ifindex) != NULL;
}

void nodes_delete(struct vault *v, int index)
{
	if (index < 0 || index >= v->nodes.total)
		return;

	v->nodes.items[index] = NULL;

	for (int i = index; i < v->nodes.total - 1; i++) {
		v->nodes.items[i] = v->nodes.items[i + 1];
		v->nodes.items[i + 1] = NULL;
	}

	v->nodes.total--;

	if (v->nodes.total > 0 && v->nodes.total == v->nodes.capacity / 4)
		nodes_resize(v, v->nodes.capacity / 2);
}

void nodes_free(struct vault *v)
{
    for (int i = 0; i < v->nodes.total - 1; i++) {
	struct node* node = v->nodes.items[i];
	node_delete(node);
	v->nodes.items[i] = NULL;
    }
    free(v->nodes.items);
}

struct vault	vault;

void vault_init(struct vault* v)
{
	certificate_init(&(v->certificate_authority));
	nodes_init(v);
}

void vault_free(struct vault* v)
{
	certificate_free(&(v->certificate_authority));
	nodes_free(v);
}


BIO*		outbio				= NULL;

void DumpPrivateKey(uint32_t level, unsigned char* source, unsigned char* name, EVP_PKEY* sk_key)
{
	if(log_level <= level)
	{
		unsigned char* raw_key = OPENSSL_malloc(EVP_PKEY_size(sk_key));
		size_t raw_len = EVP_PKEY_size(sk_key);

		if (EVP_PKEY_get_raw_private_key(sk_key, raw_key, &raw_len) == 1) {
			DumpKey(level, source, name, raw_len, raw_key);
		} else {
			lprintf(LOG_LEVEL_ERROR, "DumpPrivateKey: Failed to extract raw public key from EVP_PKEY.\n");
		}

		OPENSSL_free(raw_key);
	}
}

void DumpPublicKey(uint32_t level, unsigned char* source, unsigned char* name, EVP_PKEY* sk_key)
{
	if(log_level <= level)
	{
		unsigned char* raw_key = OPENSSL_malloc(EVP_PKEY_size(sk_key));
		size_t raw_len = EVP_PKEY_size(sk_key);

		if (EVP_PKEY_get_raw_public_key(sk_key, raw_key, &raw_len) == 1) {
			DumpKey(level, source, name, raw_len, raw_key);
		} else {
			lprintf(LOG_LEVEL_ERROR, "DumpPublicKey: Failed to extract raw public key from EVP_PKEY.\n");
		}

		OPENSSL_free(raw_key);
	}
}

void DumpKey(uint32_t level, unsigned char* source, unsigned char* name, uint32_t skey_len, unsigned char* skey)
{
	if(log_level <= level)
	{
		lprintf(level, "%s: %s (%d bytes):\n", source, name, skey_len);
		BIO_dump(outbio, skey, skey_len);
	}
}

void DumpKeys(uint32_t level, unsigned char* source, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp)
{
	if(log_level <= level)
	{
		DumpKey(level, source, "SK ", sk_len, sk);
		DumpKey(level, source, "SKE", ske_len, ske);
		DumpKey(level, source, "SKP", skp_len, skp);
	}	
}

bool MallocAndCopyPublickey(uint32_t ifindex, uint32_t* sk_len, unsigned char** sk)
{
	struct node *node = nodes_find(&vault, ifindex);
	*sk_len = 0;
	*sk = NULL;

	size_t len = EVP_PKEY_size(node->publickey);

	if ((*sk = OPENSSL_malloc(len)) == NULL) {
		BIO_printf(outbio, "Security: \t\t\tFailed to allocate memory for our node public key.\n");
		return false;
	}

	if (EVP_PKEY_get_raw_public_key(node->publickey, *sk, &len) != 1) {
		BIO_printf(outbio, "Security: \t\t\tFailed to extract our node public key.\n");
		OPENSSL_free(*sk);
		*sk = NULL;
		return false;
	}

	*sk_len = len;
	return true;
}

bool MallocAndCopyCertificate(uint32_t ifindex, uint32_t* certificate_len, unsigned char** certificate)
{
	struct node *node = nodes_find(&vault, ifindex);
	*certificate_len = 0;
	*certificate = NULL;

	if(
		(node) &&
		(node->certificate.cert_data) &&
		(node->certificate.cert_data_len > 0) &&
		(*certificate = (unsigned char*) OPENSSL_malloc(node->certificate.cert_data_len))
	)
	{
		*certificate_len = node->certificate.cert_data_len;
		memcpy(*certificate, node->certificate.cert_data, node->certificate.cert_data_len);
		return true;
	}

	return false;
}

bool MallocAndGenerateNewKey(uint32_t* key_len, unsigned char** key)
{
	*key_len = 0;
	*key = NULL;
	if(*key = OPENSSL_malloc(SYM_KEY_LEN))
	{
		if(RAND_bytes(*key, SYM_KEY_LEN) == 1)
		{
			*key_len = SYM_KEY_LEN;
			return true;
		}
		OPENSSL_free(*key);
		*key = NULL;
	}
	return false;
}

bool LoadFile(unsigned char* filename, uint32_t* data_len, unsigned char** data)
{
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tLoading %s...\n", filename);
	int fd;
	fd = open(filename, O_RDONLY);

	if(fd == -1)
	{
		lprintf(LOG_LEVEL_ERROR, "Security: \t\t\t\t%s: %s\n", strerror(errno), filename);
		return NULL;
	}

	// Get the size and reset the position to the start.
	*data_len = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	
	// Allocate some memory to hold the data.
	*data = (unsigned char*) OPENSSL_malloc(*data_len);
	int bytes_read;

	// Read it all.
	bytes_read = read(fd, *data, *data_len);
	if(bytes_read != *data_len)
		lprintf(LOG_LEVEL_ERROR, "Security: \t\t\t\tBytes read isn't file length: %s\n", filename);
	close(fd);
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\t\tloaded %u bytes (file size %u bytes).\n", bytes_read, *data_len);

	return data;
}

bool LoadCertificate(uint32_t cert_data_len, unsigned char* cert_data, BIO** certbio, X509** cert)
{
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tLoading certificate...\n");

	*certbio = NULL;
	*cert = NULL;

	// Load the certificate from memory (PEM) and cacert chain from file (PEM)
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\t\tCalling BIO_new_mem...\n");
	*certbio = BIO_new_mem_buf((void*)cert_data, cert_data_len);
	if(*certbio == NULL) {
		BIO_printf(outbio, "Security: \t\t\t\tError allocating BIO memory buffer.\n");
		return false;
	}

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\t\tCalling PEM_read_bio_x509...\n");
	*cert = PEM_read_bio_X509(*certbio, NULL, 0, NULL);
	if(*cert == NULL) {
		BIO_printf(outbio, "Security: \t\t\t\tError loading cert into memory.\n");
		BIO_free_all(*certbio);
		return false;
	}

	//lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tdone.\n");
	return true;
}

bool FreeCertificate(BIO** certbio, X509** cert)
{
	if(*cert)
	{
		X509_free(*cert);
		*cert = NULL;
	}
	if(*certbio)
	{
		BIO_free_all(*certbio);
		*certbio = NULL;
	}
}

bool CheckKey(EVP_PKEY* pkey)
{
	int keytype;
	keytype = EVP_PKEY_id(pkey);
	if(keytype != EVP_PKEY_X25519)
	{
		BIO_printf(outbio, "Security: \t\t\tWe were expecting an X25519 key, that's not what we have.\n");
		switch (keytype)
		{
			case EVP_PKEY_RSA:
				BIO_printf(outbio, "Security: \t\t\t%d bit RSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				BIO_printf(outbio, "Security: \t\t\t%d bit DSA Key\n", EVP_PKEY_bits(pkey));
				break;
			default:
				BIO_printf(outbio, "Security: \t\t\t%d bit non-RSA/DSA Key\n", EVP_PKEY_bits(pkey));
				break;
		}
		return false;
	}
	else
	{
		// BIO_printf(outbio, "Security: %d bit DH Key\n", EVP_PKEY_bits(pkey));
		return true;
	}
}

bool LoadPublicKeyFromCertificate(uint32_t cert_data_len, unsigned char* cert_data, EVP_PKEY** public_key)
{
	// Load our public key from the certificate
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tExtracting public key from certificate...\n");
	struct certificate cert;
	cert.cert_data_len = cert_data_len;
	cert.cert_data = cert_data;

	// BIO*		certbio		= NULL;
	// X509*		cert		= NULL;
	if(!LoadCertificate(cert.cert_data_len, cert.cert_data, &(cert.cert_bio), &(cert.cert)))
	{
		BIO_printf(outbio, "Security: \t\t\tError loading the certificate.\n");
		return false;
	}

	EVP_PKEY*	pkey		= NULL;

	// Extract the certificate's public key data.
	if ((pkey = X509_get_pubkey(cert.cert)) == NULL)
	{
		BIO_printf(outbio, "Security: \t\t\tError getting public key from certificate.\n");
		FreeCertificate(&(cert.cert_bio), &(cert.cert));
		return false;
	}

	// Print the public key information and the key in PEM format
	// display the key type and size here
	if(!CheckKey(pkey))
	{
		EVP_PKEY_free(pkey);
		FreeCertificate(&(cert.cert_bio), &(cert.cert));
		return false;
	}

	*public_key = pkey;

	// Extract the public key as a BIGNUM.
	// EVP_PKEY_get_size_t_param(pkey, "pub", sk_len);
	// *sk = OPENSSL_malloc(*sk_len);
	// if(EVP_PKEY_get_octet_string_param(pkey, "pub", *sk, *sk_len, sk_len) != 1)
	// {
	// 	BIO_printf(outbio, "Security: Error getting key.");
	// 	OPENSSL_free(*sk);
	// 	*sk = NULL;
	// 	*sk_len = 0;
	// 	EVP_PKEY_free(pkey);
	// 	FreeCertificate(&(cert.cert_bio), &(cert.cert));
	// 	return false;
	// }

	// Free up the loaded pkey.
	//EVP_PKEY_free(pkey);

	FreeCertificate(&(cert.cert_bio), &(cert.cert));

	//return n;
	return true;
}

bool LoadNodeCertificates(uint32_t ifindex, unsigned char* node_cert_filename, unsigned char* node_privatekey_filename)
{
	char ifname[IF_NAMESIZE];
	if(!if_indextoname(ifindex, ifname))
		lprintf(LOG_LEVEL_DEBUG, "Security: \tLoading node certificates for interface [unknown]...\n");
	else
		lprintf(LOG_LEVEL_DEBUG, "Security: \tLoading node certificates for %s...\n", ifname);

	struct node *node;
	if(nodes_exists(&vault, ifindex))
	{
		lprintf(LOG_LEVEL_DEBUG, "Security: \tThe node already exists in the vault. Unloading and overiding...\n");
		UnloadAll();
		node_delete(nodes_find(&vault, ifindex));
	}
	node = node_create(ifindex);

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tReading our node certificate data...\n");
	if(
		(!(LoadFile(node_cert_filename, &(node->certificate.cert_data_len), &(node->certificate.cert_data)))) ||
		(!(LoadFile(node_privatekey_filename, &(node->privatekey_data_len), &(node->privatekey_data))))
	)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to load the node certificate files.\n");
		node_delete(node);
		return false;
	}

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tVerifying our node certificate...\n");
	if(!VerifyCertificate(-1, node->certificate.cert_data_len, node->certificate.cert_data, NULL, 0))
	{
		BIO_printf(outbio, "Security: \t\t\tError verifying our node certificate.\n");
		node_delete(node);
		return false;
	}

	// Load up our private key.
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tLoading our node private key...\n");
	node->privatekey_bio = BIO_new_mem_buf((void*)node->privatekey_data, node->privatekey_data_len);
	if(!(node->privatekey = PEM_read_bio_PrivateKey(node->privatekey_bio, NULL, NULL, NULL)))
	{
		BIO_printf(outbio, "Security: \t\t\tError loading our node private key.\n");
		node_delete(node);
		return false;
	}
	DumpPrivateKey(LOG_LEVEL_DEBUG, "Security", "priv", node->privatekey);

	// Do some checks on the private key
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tChecking our node private key...\n");
	if(!CheckKey(node->privatekey))
	{
		BIO_printf(outbio, "Security: \t\t\tOur node private key failed the check.\n");
		node_delete(node);
		return false;
	}

	// Load our public key from the certificate
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tLoading our node public key...\n");
	if(!LoadPublicKeyFromCertificate(node->certificate.cert_data_len, node->certificate.cert_data, &node->publickey))
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to load our node public key from our node certificate.\n");
		node_delete(node);
		return false;
	}
	DumpPublicKey(LOG_LEVEL_DEBUG, "Security", "puba", node->publickey);

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tDeriving our node public key from our node private key...\n");
	unsigned char pub_bytes[32];
	size_t pub_len = sizeof(pub_bytes);
	EVP_PKEY *pub_key = NULL;
	if (
		EVP_PKEY_get_raw_public_key(node->privatekey, pub_bytes, &pub_len) != 1 ||
		(pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_bytes, pub_len)) == NULL
	) {
		BIO_printf(outbio, "Security: \t\t\tFailed to derive our node public key from our node private key.\n");
		node_delete(node);
		return false;
	}

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tComparing the node derived public key with the node certificate public key...\n");
	if(EVP_PKEY_eq(pub_key, node->publickey) != 1)
	{
		BIO_printf(outbio, "Security: \t\t\tThe nodes private key doesn't match the node certificate provided.\n");
		EVP_PKEY_free(pub_key);
		node_delete(node);
		return false;
	}

	DumpPublicKey(LOG_LEVEL_DEBUG, "Security", "pub ", node->publickey);
	DumpPrivateKey(LOG_LEVEL_DEBUG, "Security", "priv", node->privatekey);

	EVP_PKEY_free(pub_key);

	node->ifindex = ifindex;
	nodes_add(&vault, node);
	return true;
}

bool VerifyCertificate(uint32_t ifindex, uint32_t cert_data_len, unsigned char* cert_data, unsigned char* sk, int sk_len)
{
	BIO             *certbio	= NULL;
	X509            *cert		= NULL;
	X509_STORE_CTX  *vrfy_ctx	= NULL;

	int ret;

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tVerifying certificate...\n");

	if(!LoadCertificate(cert_data_len, cert_data, &certbio, &cert))
		return false;

	// Create the context structure for the validation operation.
	vrfy_ctx = X509_STORE_CTX_new();

	// Initialize the ctx structure for a verification operation:
	// Set the trusted cert store, the unvalidated cert, and any
	// potential certs that could be needed (here we set it NULL)
	X509_STORE_CTX_init(vrfy_ctx, vault.certificate_authority.cert_store, cert, NULL);

	// Check the complete cert chain can be build and validate.
	// Returns 1 on success, 0 on verification failures, and -1
	// for trouble with the ctx object (i.e. missing certificate)
	ret = X509_verify_cert(vrfy_ctx);
	// BIO_printf(outbio, "Security: Verification return code: %d\n", ret);

	// if(ret == 0 || ret == 1)
	// 	BIO_printf(outbio, "Security: Verification result text: %s\n", X509_verify_cert_error_string(vrfy_ctx->error));

	// The error handling below shows how to get failure details
	// from the offending certificate.
	if(ret == 0) {
		//  Get the offending certificate causing the failure
		X509* error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
		X509_NAME* cert_subject_name = X509_get_subject_name(error_cert);
		BIO_printf(outbio, "Security: \t\t\tVerification failed cert:\n");
		X509_NAME_print_ex(outbio, cert_subject_name, 0, XN_FLAG_MULTILINE);
		X509_NAME_free(cert_subject_name);
		X509_free(error_cert);
		BIO_printf(outbio, "\n");
	}

	// Free up all structures
	X509_STORE_CTX_free(vrfy_ctx);
	FreeCertificate(&certbio, &cert);

	if(ret == 1)
	{
		// Now check the sk provided matches the certificate.
		if(sk_len > 0 && sk != NULL)
		{
			EVP_PKEY* pkey = NULL;
			if(!LoadPublicKeyFromCertificate(cert_data_len, cert_data, &pkey))
			{
				BIO_printf(outbio, "Security: \t\t\tUnable to load public key from the provided certificate.\n");
				ret = 0;
			}
			else
			{
				EVP_PKEY* skey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, sk, sk_len);
				if(!skey)
				{
					BIO_printf(outbio, "Security: \t\t\tUnable to retrieve PKEY from the node share.\n");
					ret = 0;
				}
				else
				{
					if(EVP_PKEY_compare(skey, pkey) != 1)
					{
						BIO_printf(outbio, "Security: \t\t\tCertificate / node share doesn't match.\n");
						ret = 0;
					}
					EVP_PKEY_free(skey);
				}

				EVP_PKEY_free(pkey);
			}
		}
	}

	if(ret == 1)
	{
		//lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\t...certificate verified.\n");
		return true;
	}
	else
	{
		lprintf(LOG_LEVEL_ERROR, "Security: \t\t\tCertificate failed to verify.\n");
		return false;
	}
}

bool MallocAndGenerateSharedkeys(uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp)
{
	size_t len;
	*ske_len = SYM_KEY_LEN;
	*ske = NULL;
	*skp_len = SYM_KEY_LEN;
	*skp = NULL;

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tAllocating %u bytes for SKE and SKP...\n", SYM_KEY_LEN);
	if(	(!(*ske = (unsigned char*) OPENSSL_malloc(*ske_len))) ||
		(!(*skp = (unsigned char*) OPENSSL_malloc(*skp_len)))
	)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to allocate the memory for SKE and SKP.\n");
		if(*ske) {
			OPENSSL_free(*ske);
			*ske = NULL;
			*ske_len = 0;
		}
		if(*skp) {
			OPENSSL_free(*skp);
			*skp = NULL;
			*skp_len = 0;
		}
		return false;
	}

	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if(!kdf)
	{
		BIO_printf(outbio, "Security: \t\t\tKDF fetch failed.\n");
		OPENSSL_free(*ske);
		OPENSSL_free(*skp);
		*ske_len = 0;
		*skp_len = 0;
		return false;
	}

	EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
	if(!kdf_ctx)
	{
		BIO_printf(outbio, "Security: \t\t\tKDF context failed.\n");
		EVP_KDF_free(kdf);
		OPENSSL_free(*ske);
		OPENSSL_free(*skp);
		*ske_len = 0;
		*skp_len = 0;
		return false;
	}

	// a. Derive e2e key
	OSSL_PARAM params_e2e[] = {
		OSSL_PARAM_octet_string("key", sk, sk_len),
		OSSL_PARAM_octet_string("salt", NULL, 0),
		OSSL_PARAM_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_octet_string("info", "SUPERMAN E2E", strlen("SUPERMAN E2E")),
		OSSL_PARAM_END
	};

	len = SYM_KEY_LEN;
	int d1 = EVP_KDF_derive(kdf_ctx, *ske, len, params_e2e);
	*ske_len = len;

	// b. Derive p2p key
	OSSL_PARAM params_p2p[] = {
		OSSL_PARAM_octet_string("key", sk, sk_len),
		OSSL_PARAM_octet_string("salt", NULL, 0),
		OSSL_PARAM_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_octet_string("info", "SUPERMAN P2P", strlen("SUPERMAN P2P")),
		OSSL_PARAM_END
	};

	len = SYM_KEY_LEN;
	int d2 = EVP_KDF_derive(kdf_ctx, *skp, len, params_p2p);
	*skp_len = len;

	EVP_KDF_CTX_free(kdf_ctx);
	EVP_KDF_free(kdf);

	if(d1 != 1 || d2 != 1)
	{
		BIO_printf(outbio, "Security: \t\t\tKDF derivation failed.\n");
		OPENSSL_free(*ske);
		OPENSSL_free(*skp);
		*ske_len = 0;
		*skp_len = 0;
		return false;
	}

	return true;
}

bool MallocAndGenerateSharedkeysFromInterface(uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp)
{
	struct node *node = nodes_find(&vault, ifindex);
	if(!node)
	{
		BIO_printf(outbio, "Security: \t\t\tError obtaining node from interface.\n");
		return false;
	}
	
	size_t cmb_len;
	unsigned char* cmb = NULL;
	EVP_PKEY *sk_key;
	bool result;

	// Create a new PKEY for the remote node;
	sk_key = EVP_PKEY_new_raw_public_key(
		EVP_PKEY_X25519,   // Key type
		NULL,              // No engine
		sk,                // Pointer to raw public key bytes
		sk_len             // Length (should be 32 bytes for X25519)
	);
	if(!sk_key)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to create PKEY.\n");
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(node->privatekey, NULL);
	if(ctx == NULL)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to create EVP_PKEY context.\n");
		EVP_PKEY_free(sk_key);
		return false;
	}

	cmb_len = EVP_PKEY_get_size(node->privatekey);
	cmb = OPENSSL_malloc(cmb_len);
	if(cmb == NULL)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to allocate the memory for the computed shared key.\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(sk_key);
		return false;
	}

	if(
		EVP_PKEY_derive_init(ctx) != 1 ||
		EVP_PKEY_derive_set_peer(ctx, sk_key) != 1 ||
		EVP_PKEY_derive(ctx, cmb, &cmb_len) != 1
	)
	{
		BIO_printf(outbio, "Security: \t\t\tFailed to derive the shared key.\n");
		EVP_PKEY_CTX_free(ctx);
		OPENSSL_free(cmb);
		EVP_PKEY_free(sk_key);
		return false;
	}

	DumpKey(LOG_LEVEL_DEBUG, "Security", "pub ", sk_len, sk);
	DumpPrivateKey(LOG_LEVEL_DEBUG, "Security", "priv", node->privatekey);
	DumpKey(LOG_LEVEL_DEBUG, "Security", "cmb ", cmb_len, cmb);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(sk_key);

	result = MallocAndGenerateSharedkeys(cmb_len, cmb, ske_len, ske, skp_len, skp);

	OPENSSL_free(cmb);

	return result;
}

// unsigned char* GenerateSharedSecret(uint32_t ifindex, uint32_t cert_data_len, unsigned char* cert_data)
// {
// 	struct node *node = nodes_find(&vault, ifindex);
// 	if(!node)
// 		return NULL;

// 	BIGNUM* pubkey = LoadPublicKeyFromCertificate(cert_data_len, cert_data);
// 	if(!pubkey) return NULL;

// 	unsigned char *secret;
// 	if(!(secret = OPENSSL_malloc(sizeof(unsigned char) * (EVP_PKEY_get_size(node->privatekey)))))
// 	{
// 		BN_clear_free(pubkey);
// 		return NULL;
// 	}

// 	int secret_size;
// 	if(0 > (secret_size = DH_compute_key(secret, pubkey, node->privatekey)))
// 	{
// 		BN_clear_free(pubkey);
// 		OPENSSL_free(secret);
// 		return NULL;
// 	}

// 	BN_clear_free(pubkey);

// 	//lprintf("Security: Shared secret generated:\n");
// 	//BIO_dump(outbio, secret, secret_size);

// 	unsigned char* key1 = OPENSSL_malloc(sizeof(unsigned char) * SYM_KEY_LEN);
// 	unsigned char* key2 = OPENSSL_malloc(sizeof(unsigned char) * SYM_KEY_LEN);

// 	if(PKCS5_PBKDF2_HMAC(secret, secret_size, NULL, 0, 1000, EVP_sha256(), SYM_KEY_LEN, key1) == 0)
// 	{
// 		BIO_printf(outbio, "Security: SKE generation failed.");
// 		OPENSSL_free(key1);
// 		OPENSSL_free(key2);
// 		return false;
// 	}
// 	//lprintf("Security: Key 1 generated:\n");
// 	//BIO_dump(outbio, key1, SYM_KEY_LEN);

// 	if(PKCS5_PBKDF2_HMAC(secret, secret_size, NULL, 0, 2000, EVP_sha256(), SYM_KEY_LEN, key2) == 0)
// 	{
// 		BIO_printf(outbio, "Security: SKP generation failed.");
// 		OPENSSL_free(key1);
// 		OPENSSL_free(key2);
// 		return false;
// 	}
// 	//lprintf("Security: Key 2 generated:\n");
// 	//BIO_dump(outbio, key2, SYM_KEY_LEN);

// 	OPENSSL_free(key1);
// 	OPENSSL_free(key2);

// 	return secret;
// }

bool TestCertificate(unsigned char* cert_filename)
{
	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tTesting certificate %s...\n", cert_filename);

	uint32_t cert_data_len;
	unsigned char* cert_data;
	if(LoadFile(cert_filename, &cert_data_len, &cert_data))
	{
		// Can we verify the certificate?
		uint32_t sk_len = 0;
		unsigned char* sk = NULL;
		if(VerifyCertificate(-1, cert_data_len, cert_data, sk, sk_len))
		{
			// Certificate is valid
			BIO_printf(outbio, "Security: \t\t\tCertificate is valid.\n");
		}
		else
		{
			// Certificate is invalid
			BIO_printf(outbio, "Security: \t\t\tCertificate is invalid.\n");
			return false;
		}

		lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tLoading public key from node certificate...\n");
		EVP_PKEY* key = NULL;
		if(LoadPublicKeyFromCertificate(cert_data_len, cert_data, &key))
		{
			//BIO_printf(outbio, "Security: \t\t\tLoaded public key from node certificate:\n");
			//PEM_write_bio_PUBKEY(outbio, key);
		}
		else
		{
			BIO_printf(outbio, "Security: \t\t\tError obtaining public key from node.\n");
			return false;	
		}

		lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tExtracting the raw public key from the PKEY...\n");
		// First, get the length
		size_t size;
		if (!EVP_PKEY_get_octet_string_param(key, "pub", NULL, 0, &size)) {
			BIO_printf(outbio, "Security: \t\t\tUnable to obtain the length of the PKEY.\n");
			return false;
		}
		sk_len = size;
		
		// Allocate buffer
		sk = OPENSSL_malloc(sk_len);
		if (!sk) {
			BIO_printf(outbio, "Security: \t\t\tFailed to allocate memory for the raw public key.\n");
			return false;	
		}

		// Extract the public key
		if (!EVP_PKEY_get_octet_string_param(key, "pub", sk, sk_len, &size)) {
			BIO_printf(outbio, "Security: \t\t\tError extracting public key from PKEY.\n");
			free(sk);
			return false;
		}
		sk_len = size;

		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		lprintf(LOG_LEVEL_DEBUG, "Security: \t\t\tObtaining SKE and SKP from the SK...\n");
		if(MallocAndGenerateSharedkeysFromInterface(-1, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{

			BIO_printf(outbio, "Security: \t\t\tShared keys generated successfully.\n");
			OPENSSL_free(ske);
			OPENSSL_free(skp);
		}
		else
		{
			BIO_printf(outbio, "Security: \t\t\tError obtaining shared keys.\n");
		}

		// unsigned char* sharedSecret = GenerateSharedSecret(cert_data_len, cert_data);
		OPENSSL_free(sk);		
		OPENSSL_free(cert_data);
		EVP_PKEY_free(key);
	}
	else
	{
		// Certificate failed to load.
		BIO_printf(outbio, "Security: \t\t\tCertificate failed to load.\n");
		return false;
	}
	return true;
}

bool InitSecurity(unsigned char* ca_cert_filename)
{
	lprintf(LOG_LEVEL_DEBUG, "Security: \tInitialising Security...\n");

	vault_init(&vault);

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tReading CA certificate file...\n");
	if(
		!(LoadFile(ca_cert_filename, &(vault.certificate_authority.cert_data_len), &(vault.certificate_authority.cert_data)))
	)
	{
		DeInitSecurity();		
		return false;
	}

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tInitialising OpenSSL...\n");
	OpenSSL_add_all_algorithms();
	//ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	if(use_logfile)
		outbio = BIO_new_fp(log_file, BIO_NOCLOSE);
	else
		outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	RAND_poll();

	lprintf(LOG_LEVEL_DEBUG, "Security: \t\tLoading the CA public certificate...\n");

	// Load up the root CA's certificate.
	if(!LoadCertificate(vault.certificate_authority.cert_data_len, vault.certificate_authority.cert_data, &(vault.certificate_authority.cert_bio), &(vault.certificate_authority.cert)))
	{
		DeInitSecurity();
		return false;
	}

	// Initialize the global certificate validation store object.
	if (!(vault.certificate_authority.cert_store = X509_STORE_new()))
	{
		BIO_printf(outbio, "Security: \t\tError creating X509_STORE_CTX object.\n");
		DeInitSecurity();
		return false;
	}

	// Add our root CA to the store.
	if (X509_STORE_add_cert(vault.certificate_authority.cert_store, vault.certificate_authority.cert) != 1)
	{
		BIO_printf(outbio, "Security: \t\tError loading CA cert or chain file\n");
		DeInitSecurity();
		return false;
	}

	return true;
}

void DeInitSecurity(void)
{
	lprintf(LOG_LEVEL_DEBUG, "Security: \tDeinitialising Security...\n");
	if(outbio)
	{
		BIO_free_all(outbio);
		outbio = NULL;
	}

	vault_free(&vault);
}

#endif
