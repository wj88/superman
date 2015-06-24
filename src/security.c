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
#include <net/ip.h>

#include "packet.h"
#include "security.h"


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
	len += sizeof(struct aead_givcrypt_request) + crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += sizeof(struct scatterlist) * nfrags;

	spi->tmp = kmalloc(len, GFP_ATOMIC);
	return (spi->tmp);
}

static bool alloc_tmp_p2p(struct superman_packet_info* spi, struct crypto_ahash* ahash, int nfrags)
{
	unsigned int len;
	len = crypto_ahash_digestsize(ahash);
	len += sizeof(struct scatterlist) * nfrags;

	spi->tmp = kmalloc(len, GFP_ATOMIC);
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

static inline struct aead_givcrypt_request *tmp_givreq(struct crypto_aead *aead, u8 *iv)
{
	struct aead_givcrypt_request *req;
	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead), crypto_tfm_ctx_alignment());
	aead_givcrypt_set_tfm(req, aead);
	return req;
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

static inline struct scatterlist *givreq_sg(struct crypto_aead *aead, struct aead_givcrypt_request *req)
{
        return (void *)ALIGN((unsigned long)(req + 1) + crypto_aead_reqsize(aead), __alignof__(struct scatterlist));
}

bool UpdateBroadcastKey(uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	struct security_table_entry* entry;
	uint8_t flag = 0;

	// If we already have a valid entry and we're not being asked to overwrite it.
	if(!overwrite && GetSecurityTableEntry(INADDR_BROADCAST, &entry) && entry->flag >= 3)
		return true;

	// Determine whether we have an sk.
	if(sk_len > 0 && sk != NULL)
	{
		// Do we also have ske and skp?
		if(ske_len > 0 && skp_len > 0 && ske != NULL && skp != NULL)
			flag = 3;
		else
			flag = 2;
	}
	else
		flag = 0;

	return UpdateOrAddSecurityTableEntry(INADDR_BROADCAST, flag, sk_len, sk, ske_len, ske, skp_len, skp, 0, 0);
}

bool GetBroadcastKey(uint32_t* sk_len, unsigned char** sk)
{
	struct security_table_entry* entry;
	if(!GetSecurityTableEntry(INADDR_BROADCAST, &entry))
		return false;
	*sk_len = entry->sk_len;
	*sk = entry->sk;
	return true;
}

/*
unsigned int AddE2ESecurityDone(struct superman_packet_callback_arg* spca, int err, bool callback)
{
	struct superman_header* shdr;
	struct sk_buff* skb;
	void* payload;

	// Grab the skb
	skb = spca->skb;

	if(err == 0)
	{
		// Start address of the superman header;
		shdr = (struct superman_header*) skb_transport_header(skb);

		// Payload length (contents of Superman packet)
		payload = ((unsigned char*) shdr) + sizeof(struct superman_header);

		// The bloated payload (payload rounded up to the nearest block size)
		bloated_payload = ALIGN(shdr->payload_len + 2, ALIGN(crypto_aead_blocksize(aead), 4));

		// Copy the auth data to the end of the payload so we can free up the remaining block parts.
		memcpy(payload + shdr->payload_len, payload + ALIGN(shdr->payload_len + 2, ALIGN(crypto_aead_blocksize(aead), 4)), AUTH_LEN);

		// Trim the excess off the end, leaving the encrypted payload and the auth data.
		pskb_trim(skb, skb->len - (bloated_payload - shdr->payload_len));

		// Inject the packet.
		if(callback)
			spca->okfn(skb, spca->arg);

		// Free up allocated memory.
		kfree(spca);

		return NF_ACCEPT;
	}
	else
	{
		// Free up allocated memory.
		kfree(spca);

		// Free up allocated memory.
		if(callback)
			kfree_skb(skb);

		return NF_DROP;
	}
}

static void addE2ESecurityDone(struct crypto_async_request *base, int err)
{
	struct superman_packet_callback_arg *spca = base->data;
	AddE2ESecurityDone(spca, err, true);
}

unsigned int AddE2ESecurity(struct sk_buff* skb, int (*okfn)(struct sk_buff*, void*), void* arg, bool force_callback, bool force_broadcast)
{
	struct security_table_entry* entry;
	int addr_type;
	int err;
	int i;
	void* payload;
	__be16 payload_len;
	int alen;
	int blksize;
	int clen;
	int plen;
	int tlen;
	int assoclen;
	int nfrags;
	u8 *iv;
	__be32 *seqhi;
	int seqhilen;
	struct sk_buff* trailer;
	uint8_t* tail;
	struct scatterlist *sg;
	struct scatterlist *asg;
	void* nhdr;
	struct superman_header* shdr;
	struct aead_givcrypt_request *req;
	struct superman_packet_callback_arg* spca;

	// Start address of the network and superman headers;
	nhdr = skb_network_header(skb);
	shdr = (struct superman_header*) skb_transport_header(skb);

	// Determine which key we should be using.
	addr_type = ip_chk_addr(ip_hdr(skb)->daddr);
	if(addr_type == IS_MYADDR || addr_type == IS_LOOPBACK)
		return NF_ACCEPT;
	else if(addr_type == IS_BROADCAST || addr_type == IS_MULTICAST || force_broadcast)
	{
		if((broadcast_key_len == 0) || !(broadcast_key) || (crypto_aead_setkey(aead, broadcast_key, broadcast_key_len) != 0))
			return NF_DROP;
	}
	else
	{
		if(!GetSecurityTableEntry(ip_hdr(skb)->daddr, &entry))
		{
			// Enqueue the packet
			// Send an SK Request
			return NF_STOLEN;
		}	
		else if(crypto_aead_setkey(aead, entry->ske, entry->ske_len) != 0)
			return NF_DROP;
	}

	// Payload length (contents of Superman packet)
	payload = ((void*) shdr) + sizeof(struct superman_header);
	payload_len = shdr->payload_len;

	// Size of the auth data
	alen = AUTH_LEN;

	// Size of a single block
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);

	// clen = contents length?
	// The bloated payload (payload rounded up to the nearest block size)
	clen = ALIGN(payload_len + 2, blksize);

	// Size of the padding added to make contents up to block size
	plen = clen - payload_len;

	// Total size of contents with auth bytes added
	tlen = clen + alen;

	// Size of the associated data
	assoclen = sizeof(struct iphdr) + sizeof(struct superman_header);

	// Grab the scatterlist length whilst ensuring we have space for the currently not added data.
	nfrags = skb_cow_data(skb, padding_len + AUTH_LEN, &trailer);
	if(nfrags < 0)
		return false;

	// Move the alen to just after the last block
	memcpy(payload + clen, payload + shdr->payload_len, alen);

	// Fill the padding with known data.
	tail = skb_tail_pointer(trailer);
	for (i = 0; i < plen - 2 - alen; i++)
		tail[i] = i + 1;
	tail[plen - 2] = plen - 2;
	tail[plen - 1] = *skb_mac_header(skb);

	// Reserve the space in the skb for our encrypted data to fill the block size.
	pskb_put(skb, trailer, clen - payload_len + alen);

	// We need some temporary memory to store stuff. Allocate the memory then divide it up.
	sglists = 1;
	seqhilen = 0;
	spca = alloc_tmp_e2e(skb, aead, nfrags + sglists, seqhilen, okfn, arg);
	seqhi = tmp_seqhi(spca->tmp);
	iv = tmp_iv(aead, spca->tmp, seqhilen);
	req = tmp_givreq(aead, iv);
	asg = givreq_sg(aead, req);
	sg = asg + sglists;

	// No longer checksumed
	skb->ip_summed = CHECKSUM_NONE;

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, offset from where the real payload data.
	skb_to_sgvec(skb, sg, skb_transport_offset(skb) + sizeof(struct superman_header), clen + alen);

	// Initialise the associated data scatterlist with the header stuff (all of the headers).
	sg_init_one(asg, nhdr, payload - nhdr);

	// Setup aead
	aead_givcrypt_set_callback(req, 0, addE2ESecurityDone, spca);
	aead_givcrypt_set_crypt(req, sg, sg, clen, iv);
	aead_givcrypt_set_assoc(req, asg, assoclen);
	aead_givcrypt_set_giv(req, payload, 0);

	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS)
		return NF_STOLEN;

	// Process the result and free up any allocated memory.
	return AddE2ESecurityDone(spca, err, force_callback);
}
*/

unsigned int RemoveE2ESecurityDone(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool), int err)
{
	bool result = false;
	int blksize;
	int aligned_payload_len;

	if(err == 0)
	{
		// Size of a single block
		blksize = ALIGN(crypto_aead_blocksize(aead), 4);

		// The bloated payload (payload rounded up to the nearest block size)
		aligned_payload_len = ALIGN(spi->shdr->payload_len, blksize);

		// Trim the excess off the end, leaving the unencrypted payload and headers.
		pskb_trim(spi->skb, spi->skb->len - (aligned_payload_len - spi->shdr->payload_len) - AUTH_LEN);

		result = true;
	}

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

static void removeE2ESecurityDone(struct crypto_async_request *base, int err)
{
	struct superman_packet_info* spi = base->data;
	unsigned int (*callback)(struct superman_packet_info*, bool) = spi->arg;
	spi->arg = NULL;
	RemoveE2ESecurityDone(spi, callback, err);
}

unsigned int RemoveE2ESecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool))
{
	int err;
	int i;
	int blksize;
	int aligned_payload_len;
	int padding_len;
	int assoc_len;
	int nfrags;
	u8 *iv;
	__be32 *seqhi;
	int seqhilen;
	struct sk_buff* trailer;
	uint8_t* tail;
	struct scatterlist *sg;
	struct scatterlist *asg;
	int sglists;
	struct aead_request *req;

/*
			Transformation during E2E removal.

	------------------------------------------------------------------------
	| IP Header | SUPERMAN Header | Encrypted Payload		| Auth |
	------------------------------------------------------------------------
					|
					v
			      ---------------------
			      | RemoveE2ESecurity |
			      ---------------------
					|
					v
	----------------------------------------------------------------------------------
	| IP Header | SUPERMAN Header | Encrypted Payload		| Padding | Auth |
	----------------------------------------------------------------------------------
					|
					v
	----------------------------------------------------------------------------------
	| IP Header | SUPERMAN Header | Payload				| Padding | Auth |
	----------------------------------------------------------------------------------
					|
					v
			    -------------------------
			    | RemoveE2ESecurityDone |	// The bloated payload (payload rounded up to the nearest block size)
	aligned_payload_len = ALIGN(spi->shdr->payload_len, blksize);

			    -------------------------
					|
					v
	-----------------------------------------------------------------
	| IP Header | SUPERMAN Header | Payload				|
	-----------------------------------------------------------------
*/

	// Determine which key we should be using.

	// If we don't need to secure this packet, accept it.
	if(!spi->secure_packet)
	{
		spi->result = NF_ACCEPT;
		return NF_ACCEPT;
	}

	// If we don't have the security details.
	if(!spi->has_security_details)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// We have a key to use, load it into the crypto process.
	if(crypto_aead_setkey(aead, spi->security_details->ske, spi->security_details->ske_len) != 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}
	
	// Size of a single block
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);

	// The bloated payload (payload rounded up to the nearest block size)
	aligned_payload_len = ALIGN(spi->shdr->payload_len, blksize);

	// Size of the padding added to make contents up to block size
	padding_len = aligned_payload_len - spi->shdr->payload_len;

	// Size of the associated data
	assoc_len = sizeof(struct iphdr) + sizeof(struct superman_header);

	// Grab the scatterlist length whilst ensuring we have space for the currently not added data padding data.
	nfrags = skb_cow_data(spi->skb, padding_len, &trailer);
	if(nfrags < 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Reserve the space in the skb for our padding to fill the block size.
	tail = pskb_put(spi->skb, trailer, padding_len);

	// Make sure the buffer is linear or direct manipulation will likely fail.
	skb_linearize(spi->skb);

	// Move the auth data from the end of the payload to the end of the padding.
	skb_copy_bits(spi->skb, assoc_len + spi->shdr->payload_len, (tail + padding_len) - AUTH_LEN, AUTH_LEN);

	// Fill the padding with known data.
	for (i = 0; i < padding_len; i++)
		tail[i - AUTH_LEN] = i + 1;
	
	// We need some temporary memory to store stuff. Allocate the memory then divide it up.
	sglists = 1;
	seqhilen = 0;

	// Allocate some memory attached to spi->tmp to host the scatter list.
	if(!alloc_tmp_e2e(spi, aead, nfrags + sglists, seqhilen))
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}
	seqhi = tmp_seqhi(spi->tmp);
	iv = tmp_iv(aead, spi->tmp, seqhilen);
	req = tmp_req(aead, iv);
	asg = req_sg(aead, req);
	sg = asg + sglists;

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, offset from where the real payload data.
	skb_to_sgvec(spi->skb, sg, assoc_len, aligned_payload_len + AUTH_LEN);

	// Initialise the associated data scatterlist with the header stuff (all of the headers).
	sg_init_one(asg, skb_network_header(spi->skb), assoc_len);

	// Setup aead
	aead_request_set_callback(req, 0, removeE2ESecurityDone, spi);
	aead_request_set_crypt(req, sg, sg, aligned_payload_len, iv);
	aead_request_set_assoc(req, asg, assoc_len);

	// Pop the callback into the spi.
	spi->arg = callback;

	// Attempt to perform the decrypt process.
	err = crypto_aead_decrypt(req);

	// If we're told it's in progress, it is being performed asyncronously... steal the packet.
	if (err == -EINPROGRESS)
	{
		spi->result = NF_STOLEN;
	}	
	// Crypto finished immediately, go straight to the end. 
	else
	{
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
		// Make sure there is space for our HMAC to go at the end of the data.
		struct sk_buff* tailer;
		if(skb_cow_data(spi->skb, HMAC_LEN, &tailer) >= 0)
		{
			// Grab the space for the correct number of bytes. 
			unsigned char* tail = pskb_put(spi->skb, tailer, HMAC_LEN);

			// Copy the HMAC into the allocated space.
			memcpy(tail, spi->tmp, HMAC_LEN);

			result = true;
		}
	}

	kfree(spi->tmp);
	spi->tmp = NULL;

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

void addP2PSecurityDone(struct crypto_async_request *req, int err)
{
	struct superman_packet_info* spi = req->data;
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

	// Determine which key we should be using.

	// If we don't need to secure this packet, accept it.
	if(!spi->secure_packet)
	{
		spi->result = NF_ACCEPT;
		return NF_ACCEPT;
	}

	// If we don't have the security details.
	if(!spi->has_security_details)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// We have a key to use, load it into the crypto process.
	if(crypto_ahash_setkey(ahash, spi->security_details->skp, spi->security_details->skp_len) != 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Grab the scatterlist length.
	nfrags = skb_cow_data(spi->skb, 0, NULL);
	if(nfrags < 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Allocate some memory attached to spi->tmp to host the resulting hash and the scatter list.
	if(!alloc_tmp_p2p(spi, ahash, nfrags))
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Grab a reference to the hash buffer portion of our memory allocation
	hash_buffer = spi->tmp;

	// Grab a reference to the scatter list portion of our memory allocation
	sg = (spi->tmp + crypto_ahash_digestsize(ahash));

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, from the end of the network header, including everything else.
	skb_to_sgvec(spi->skb, sg, skb_transport_offset(spi->skb), spi->skb->len - sizeof(struct iphdr));

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
		spi->result = NF_STOLEN;
	}	
	// Crypto finished immediately, go straight to the end. 
	else
	{
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
		unsigned char* storedHMAC; // = payload + shdr->payload_len + AUTH_LEN;
		unsigned char* calcHMAC = spi->tmp;

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
						result = false;
						break;
					}
				}

			}
			kfree(storedHMAC);
		}

		// Trim the hmac off the end.
		pskb_trim(spi->skb, spi->skb->len - HMAC_LEN);
	}

	kfree(spi->tmp);
	spi->tmp = NULL;

	if(result && spi->result != NF_STOLEN)
		spi->result = NF_ACCEPT;
	else if(!result && spi->result != NF_STOLEN)
		spi->result = NF_DROP;

	return callback(spi, result);
}

void removeP2PSecurityDone(struct crypto_async_request *req, int err)
{
	struct superman_packet_info* spi = req->data;
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

	// Determine which key we should be using.

	// If we don't need to secure this packet, accept it.
	if(!spi->secure_packet)
	{
		spi->result = NF_ACCEPT;
		return NF_ACCEPT;
	}

	// If we don't have the security details.
	if(!spi->has_security_details)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// We have a key to use, load it into the crypto process.
	if(crypto_ahash_setkey(ahash, spi->security_details->skp, spi->security_details->skp_len) != 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Grab the scatterlist length.
	nfrags = skb_cow_data(spi->skb, 0, NULL);
	if(nfrags < 0)
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Allocate some memory attached to spi->tmp to host the resulting hash and the scatter list.
	if(!alloc_tmp_p2p(spi, ahash, nfrags))
	{
		spi->result = NF_DROP;
		return NF_DROP;
	}

	// Grab a reference to the hash buffer portion of our memory allocation
	hash_buffer = spi->tmp;

	// Grab a reference to the scatter list portion of our memory allocation
	sg = (spi->tmp + crypto_ahash_digestsize(ahash));

	// Initialise the contents scatterlist with the number of fragments with have in our skb.
	sg_init_table(sg, nfrags);

	// Populate the contents scatterlist from the skb, from the end of the network header, including everything else.
	skb_to_sgvec(spi->skb, sg, skb_transport_offset(spi->skb), spi->skb->len - sizeof(struct iphdr) - HMAC_LEN);

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
		spi->result = NF_STOLEN;
	}	
	// Crypto finished immediately, go straight to the end. 
	else
	{
		spi->arg = NULL;
		spi->result = RemoveP2PSecurityDone(spi, callback, err);
	}

	return spi->result;
}

bool InitSecurity(void)
{
	UpdateBroadcastKey(0, NULL, 0, NULL, 0, NULL, true);

	aead = crypto_alloc_aead(AEAD_ALG_NAME, 0, 0);
	if(IS_ERR(aead))
	{
		printk(KERN_ERR "SUPERMAN: Security - Failed to alloc aead.\n"); 
		return false;
	}

	if(crypto_aead_setauthsize(aead, AUTH_LEN) != 0)
	{
		printk(KERN_ERR "SUPERMAN: Security - Failed to set auth size.\n"); 
		DeInitSecurity();
		return false;
	}

	ahash = crypto_alloc_ahash("hmac(sha256)", 0, 0);
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "security.h"

uint32_t	ca_cert_data_len		= 0;
unsigned char*	ca_cert_data			= NULL;
uint32_t	node_cert_data_len		= 0;
unsigned char*	node_cert_data			= NULL;
uint32_t	node_dh_privatekey_data_len	= 0;
unsigned char*	node_dh_privatekey_data		= NULL;

BIO*		outbio				= NULL;
BIO*		ca_certbio			= NULL;
X509*		ca_cert				= NULL;
X509_STORE*	ca_store			= NULL;

BIO*		node_privatekeybio		= NULL;
EVP_PKEY*	node_privatekey			= NULL;
DH*		node_privatekey_dh		= NULL;
BIGNUM*		node_publickey			= NULL;

bool MallocAndCopyPublickey(uint32_t* sk_len, unsigned char** sk)
{
	*sk_len = 0;
	*sk = NULL;

	if(
		(node_publickey) &&
		((*sk_len = BN_num_bytes(node_publickey)) > 0) &&
		(*sk = malloc(*sk_len))
	)
	{
		BN_bn2bin(node_publickey, *sk);
		return true;
	}

	*sk_len = 0;
	return false;
}

bool MallocAndCopyCertificate(uint32_t* certificate_len, unsigned char** certificate)
{
	*certificate_len = 0;
	*certificate = NULL;

	if(
		(node_cert_data) &&
		(node_cert_data_len > 0) &&
		(*certificate = (unsigned char*) malloc(node_cert_data_len))
	)
	{
		*certificate_len = node_cert_data_len;
		memcpy(*certificate, node_cert_data, node_cert_data_len);
		return true;
	}

	return false;
}

bool MallocAndGenerateNewKey(uint32_t* key_len, unsigned char** key)
{
	*key_len = 0;
	*key = NULL;
	if(*key = malloc(SYM_KEY_LEN))
	{
		if(RAND_bytes(*key, SYM_KEY_LEN) == 1)
		{
			*key_len = SYM_KEY_LEN;
			return true;
		}
		free(*key);
		*key = NULL;
	}
	return false;
}

bool LoadFile(unsigned char* filename, uint32_t* data_len, unsigned char** data)
{
	int fd;
	struct stat file_info;

	if (access(filename, F_OK) != 0)
	{
		if (errno == ENOENT) 
			printf("Security: %s does not exist.\n", filename);
		else if (errno == EACCES) 
			printf("Security: %s is not accessible.\n", filename);
		return NULL;
	}
	if (access(filename, R_OK) != 0)
	{
		printf("Security: %s is not readable (access denied).\n", filename);
		return NULL;
	}

	fd = open(filename, O_RDONLY);
	fstat(fd, &file_info);
	*data_len = file_info.st_size;
	*data = (unsigned char*) malloc(*data_len);
	read(fd, data, data_len);
	close(fd);

	return data;
}

bool LoadCertificate(unsigned char* cert_data, BIO** certbio, X509** cert)
{
	*certbio = NULL;
	*cert = NULL;

	// Load the certificate from memory (PEM)
        // and cacert chain from file (PEM)
	*certbio = BIO_new_mem_buf((void*)cert_data, -1);
	if (!(*cert = PEM_read_bio_X509(*certbio, NULL, 0, NULL))) {
		BIO_printf(outbio, "Security: Error loading cert into memory\n");
		BIO_free_all(*certbio);
		return false;
	}

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
	if(pkey->type != EVP_PKEY_DH)
	{
		BIO_printf(outbio, "Security: We were expecting a Diffie Hellman key, that's not what we have.\n");		
		switch (pkey->type)
		{
			case EVP_PKEY_RSA:
				BIO_printf(outbio, "Security: \t%d bit RSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				BIO_printf(outbio, "Security: \t%d bit DSA Key\n", EVP_PKEY_bits(pkey));
				break;
			default:
				BIO_printf(outbio, "Security: \t%d bit non-RSA/DSA Key\n", EVP_PKEY_bits(pkey));
				break;
		}
		return false;
	}
	else
	{
		BIO_printf(outbio, "Security: %d bit DH Key\n", EVP_PKEY_bits(pkey));
		return true;
	}
}

BIGNUM* GetNodeShare(unsigned char* cert_data)
{
	// Load our public key from the certificate
	printf("Security: Extracting DH public key from certificate...\n");
	BIO*		certbio		= NULL;
	X509*		cert		= NULL;
	if(!LoadCertificate(cert_data, &certbio, &cert))
	{
		return NULL;
	}

	EVP_PKEY*	pkey		= NULL;

	// Extract the certificate's public key data.
	if ((pkey = X509_get_pubkey(cert)) == NULL)
	{
		BIO_printf(outbio, "Security: Error getting public key from certificate");
		FreeCertificate(&certbio, &cert);
		return NULL;
	}

	// Print the public key information and the key in PEM format
	// display the key type and size here
	if(!CheckKey(pkey))
	{
		EVP_PKEY_free(pkey);
		FreeCertificate(&certbio, &cert);
		return NULL;
	}

	DH *dh = EVP_PKEY_get1_DH(pkey);
	BIGNUM* n = BN_dup(dh->pub_key);
	EVP_PKEY_free(pkey);
	FreeCertificate(&certbio, &cert);
	return n;
}

bool VerifyCertificate(unsigned char* cert_data, unsigned char* node_share, int node_share_len)
{
	//X509          	*error_cert	= NULL;
	BIO             *certbio	= NULL;
	X509            *cert		= NULL;
	//X509_NAME    	*certsubject	= NULL;
	X509_STORE_CTX  *vrfy_ctx	= NULL;

	int ret;

	printf("Security: Verifying certificate...\n");
	
	if(!LoadCertificate(cert_data, &certbio, &cert))
		return false;

	// Create the context structure for the validation operation.
	vrfy_ctx = X509_STORE_CTX_new();

	// Initialize the ctx structure for a verification operation:
	// Set the trusted cert store, the unvalidated cert, and any
	// potential certs that could be needed (here we set it NULL)
	X509_STORE_CTX_init(vrfy_ctx, ca_store, cert, NULL);

	// Check the complete cert chain can be build and validated.
	// Returns 1 on success, 0 on verification failures, and -1
	// for trouble with the ctx object (i.e. missing certificate)
	ret = X509_verify_cert(vrfy_ctx);
	BIO_printf(outbio, "Security: Verification return code: %d\n", ret);

	if(ret == 0 || ret == 1)
		BIO_printf(outbio, "Security: Verification result text: %s\n", X509_verify_cert_error_string(vrfy_ctx->error));

	// The error handling below shows how to get failure details
	// from the offending certificate.
	/*
	if(ret == 0) {
		//  get the offending certificate causing the failure
		error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
		certsubject = X509_NAME_new();
		certsubject = X509_get_subject_name(error_cert);
		BIO_printf(outbio, "Verification failed cert:\n");
		X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
		BIO_printf(outbio, "\n");
	}
	*/

	// Free up all structures
	X509_STORE_CTX_free(vrfy_ctx);
	FreeCertificate(&certbio, &cert);

	if(ret == 1)
	{
		// Now check the node_share provided matches the certificate.
		if(node_share != NULL)
		{
			BIGNUM* shareProvided = BN_mpi2bn(node_share, node_share_len, NULL);
			BIGNUM* shareDerived = GetNodeShare(cert_data);
			ret = (BN_cmp(node_privatekey_dh->pub_key, node_publickey));
			BN_free(shareProvided);
			BN_free(shareDerived);

			if(ret == 0)
				ret = 1;
			else
			{
				BIO_printf(outbio, "Security: Certificate / node share doesn't match.");
				ret = 0;
			}
		}
	}

	if(ret == 1)
	{
		printf("Security: ...certificate verified.\n");
		return true;
	}
	else
	{
		printf("Security: ...certificate failed to verify.\n");
		return false;
	}
}

bool MallocAndGenerateSharedkeys(uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp)
{
	*ske_len = SYM_KEY_LEN;
	*ske = NULL;
	*skp_len = SYM_KEY_LEN;
	*skp = NULL;

	if(	(!(*ske = (unsigned char*) malloc(*ske_len))) ||
		(!(*skp = (unsigned char*) malloc(*skp_len)))
	)
	{
		*ske_len = 0;
		if(*ske) {
			free(*ske);
			*ske = NULL;
		}
		*skp_len = 0;
		if(*skp) {
			free(*skp);
			*skp = NULL;
		}
		return false;
	}

	// https://www.openssl.org/docs/crypto/PKCS5_PBKDF2_HMAC.html

	PKCS5_PBKDF2_HMAC_SHA1(sk, sk_len, NULL, 0, 1000, *ske_len, *ske);
	printf("Security: SKE generated:\n");
	BIO_dump(outbio, *ske, *ske_len);

	PKCS5_PBKDF2_HMAC_SHA1(sk, sk_len, NULL, 0, 2000, *skp_len, *skp);
	printf("Security: SKP generated:\n");
	BIO_dump(outbio, *skp, *skp_len);

	return true;
}

bool MallocAndDHAndGenerateSharedkeys(uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp)
{
	uint32_t cmb_len = DH_size(node_privatekey_dh);
	unsigned char* cmb = NULL;
	BIGNUM* sk_bn = NULL;
	bool result;

	if(
		(!(sk_bn = BN_mpi2bn(sk, sk_len, NULL))) ||
		(!(cmb = (unsigned char*) malloc(cmb_len))) ||
		(0 > (cmb_len = DH_compute_key(cmb, sk_bn, node_privatekey_dh)))
	)
	{
		if(sk_bn) {
			BN_free(sk_bn);
			sk_bn = NULL;
		}
		cmb_len = 0;
		if(cmb) {
			free(cmb);
			cmb = NULL;
		}
		return false;
	}

	BN_free(sk_bn);
	
	result = MallocAndDHAndGenerateSharedkeys(cmb_len, cmb, ske_len, ske, skp_len, skp);

	free(cmb);

	return result;
}

unsigned char* GenerateSharedSecret(unsigned char* cert_data)
{
	BIGNUM* pubkey = GetNodeShare(cert_data);
	if(!pubkey) return NULL;

	unsigned char *secret;
	if(!(secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(node_privatekey_dh)))))
	{
		BN_free(pubkey);
		return NULL;
	}

	int secret_size;
	if(0 > (secret_size = DH_compute_key(secret, pubkey, node_privatekey_dh)))
	{
		BN_free(pubkey);
		OPENSSL_free(secret);
		return NULL;
	}

	BN_free(pubkey);

	printf("Security: Shared secret generated:\n");
	BIO_dump(outbio, secret, secret_size);


	// https://www.openssl.org/docs/crypto/PKCS5_PBKDF2_HMAC.html

	unsigned char* key1 = OPENSSL_malloc(sizeof(unsigned char) * SYM_KEY_LEN);
	unsigned char* key2 = OPENSSL_malloc(sizeof(unsigned char) * SYM_KEY_LEN);

	PKCS5_PBKDF2_HMAC_SHA1(secret, secret_size, NULL, 0, 1000, SYM_KEY_LEN, key1);
	printf("Security: Key 1 generated:\n");
	BIO_dump(outbio, key1, SYM_KEY_LEN);

	PKCS5_PBKDF2_HMAC_SHA1(secret, secret_size, NULL, 0, 2000, SYM_KEY_LEN, key2);
	printf("Security: Key 2 generated:\n");
	BIO_dump(outbio, key2, SYM_KEY_LEN);

	OPENSSL_free(key1);
	OPENSSL_free(key2);

	return secret;
}

bool TestCertificate(unsigned char* cert_filename)
{
	uint32_t cert_data_len;
	unsigned char* cert_data;
	if(LoadFile(cert_filename, &cert_data_len, &cert_data))
	{
		// Can we verify the certificate?
		if(VerifyCertificate(cert_data, NULL, 0))
		{
			unsigned char* sharedSecret = GenerateSharedSecret(cert_data);

			OPENSSL_free(sharedSecret);
		}

		free(cert_data);
	}
}

bool InitSecurity(unsigned char* ca_cert_filename, unsigned char* node_cert_filename, unsigned char* node_dh_privatekey_filename)
{
	printf("Security: Reading certificate data...\n");
	if(
		(!(LoadFile(ca_cert_filename, &ca_cert_data_len, &ca_cert_data))) ||
		(!(LoadFile(node_cert_filename, &node_cert_data_len, &node_cert_data))) ||
		(!(LoadFile(node_dh_privatekey_filename, &node_dh_privatekey_data_len, &node_dh_privatekey_data)))
	)
	{
		DeInitSecurity();
		return false;
	}

	printf("Security: Initialising OpenSSL...\n");

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	RAND_poll();

	printf("Security: Loading the CA public certificate...\n");

	// Load the up root CA's certificate.
	if(!LoadCertificate(ca_cert_data, &ca_certbio, &ca_cert))
	{
		DeInitSecurity();
		return false;
	}

	// Initialize the global certificate validation store object.
	if (!(ca_store = X509_STORE_new()))
	{
		BIO_printf(outbio, "Security: Error creating X509_STORE_CTX object\n");
		DeInitSecurity();
		return false;
	}

	// Add our root CA to the store.
	if (X509_STORE_add_cert(ca_store, ca_cert) != 1)
	{
		BIO_printf(outbio, "Security: Error loading CA cert or chain file\n");
		DeInitSecurity();
		return false;
	}

	printf("Security: Verifying our node certificate...\n");
	if(!VerifyCertificate(node_cert_data, NULL, 0))
	{
		BIO_printf(outbio, "Security: Error verifying certificate\n");
		DeInitSecurity();
		return false;
	}

	// Load up our private key.
	printf("Security: Loading DH private key...\n");
	node_privatekeybio = BIO_new_mem_buf((void*)node_dh_privatekey_data, -1);
	if(!(node_privatekey = PEM_read_bio_PrivateKey(node_privatekeybio, NULL, NULL, NULL)))
	{
		BIO_printf(outbio, "Security: Error loading node private key\n");
		DeInitSecurity();
		return false;
	}

	// Do some checks on the private key
	if(!CheckKey(node_privatekey))
	{
		DeInitSecurity();
		return false;
	}		
	else
	{
//		if(!PEM_write_bio_PrivateKey(outbio, node_privatekey, NULL, NULL, 0, 0, NULL))
//			BIO_printf(outbio, "Error writing private key data in PEM format");
		node_privatekey_dh = EVP_PKEY_get1_DH(node_privatekey);
	}

	// Load our public key from the certificate
	if(!(node_publickey = GetNodeShare(node_cert_data)))
	{
		DeInitSecurity();
		return false;
	}
	
	printf("Security: Comparing the node private key with the node certificate...\n");
	if(BN_cmp(node_privatekey_dh->pub_key, node_publickey) != 0)
	{
		BIO_printf(outbio, "Security: The nodes private key doesn't match with the node certificate provided.");
		DeInitSecurity();
		return false;
	}
	else
	{
		printf("Security: ...key match.\n");
	}

	//printf("Security: Testing shared secret generator...\n");
	//unsigned char* secret = GenerateSharedSecret(node_cert_data);
	//OPENSSL_free(secret);

	//printf("Security: Extracting DH public key...\n");
	//ExtractPublicKey(node_cert_data);

	return true;
}

void DeInitSecurity(void)
{
	printf("Security: Unloading...\n");

	if(ca_store)
	{
		X509_STORE_free(ca_store);
		ca_store = NULL;
	}

	FreeCertificate(&ca_certbio, &ca_cert);

	if(outbio)
	{
		BIO_free_all(outbio);
		outbio = NULL;
	}
	if(ca_cert_data)
	{
		free(ca_cert_data);
		ca_cert_data = NULL;
	}
	if(node_cert_data)
	{
		free(node_cert_data);
		node_cert_data = NULL;
	}
	if(node_dh_privatekey_data)
	{
		free(node_dh_privatekey_data);
		node_dh_privatekey_data = NULL;
	}
	if(node_privatekeybio)
	{
		BIO_free_all(node_privatekeybio);
		node_privatekeybio = NULL;
	}
	if(node_privatekey)
	{
		EVP_PKEY_free(node_privatekey);
		node_privatekey = NULL;
	}
	if(node_publickey)
	{
		BN_free(node_publickey);
		node_publickey = NULL;
	}
}

#endif
