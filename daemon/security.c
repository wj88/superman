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

#define SYM_KEY_LEN 32

unsigned char*	ca_cert_data		= NULL;
unsigned char*	node_cert_data		= NULL;
unsigned char*	node_dh_privatekey_data	= NULL;

BIO*		outbio			= NULL;
BIO*		ca_certbio		= NULL;
X509*		ca_cert			= NULL;
X509_STORE*	ca_store		= NULL;

BIO*		node_privatekeybio	= NULL;
EVP_PKEY*	node_privatekey		= NULL;
DH*		node_privatekey_dh	= NULL;
BIGNUM*		node_publickey		= NULL;

int GetPublickeyLen()
{
	if(node_publickey != NULL)
		return BN_num_bytes(node_publickey);
	else
		return 0;
}

void GetPublickey(unsigned char* dest)
{
	if(node_publickey != NULL && dest != NULL)
		BN_bn2bin(node_publickey, dest); 
}

unsigned char* LoadFile(unsigned char* filename)
{
	int fd;
	struct stat file_info;
	unsigned char* data = NULL;

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
	data = (unsigned char*)malloc(file_info.st_size);
	read(fd, data, file_info.st_size);
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


		printf("Security: ... certificate verified.\n");
		return true;
	}
	else
	{
		printf("Security: ... certificate failed to verify.\n");
		return false;
	}
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
	unsigned char* cert_data = LoadFile(cert_filename);

	// Can we verify the certificate?
	if(VerifyCertificate(cert_data, NULL, 0))
	{

		unsigned char* sharedSecret = GenerateSharedSecret(cert_data);

		OPENSSL_free(sharedSecret);

	}

	free(cert_data);
}

bool InitSecurity(unsigned char* ca_cert_filename, unsigned char* node_cert_filename, unsigned char* node_dh_privatekey_filename)
{
	printf("Security: Reading certificate data...\n");
	if(
		(!(ca_cert_data = LoadFile(ca_cert_filename))) ||
		(!(node_cert_data = LoadFile(node_cert_filename))) ||
		(!(node_dh_privatekey_data = LoadFile(node_dh_privatekey_filename)))
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

void DeInitSecurity()
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

