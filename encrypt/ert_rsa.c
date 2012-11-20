#include "ert_rsa.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#ifdef __OPENSSL_SUPPORT

unsigned char* rsa_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	unsigned char *p_out;
	int ret;
	RSA *p_rsa;
	int rsa_len;
	int flen;
	BIO *bio = NULL;
    //bio = BIO_new(BIO_s_file());
	//BIO_read_filename(bio, key);
	//bio = BIO_new(BIO_s_mem());
	bio = BIO_new_mem_buf(encrypt_key, -1);
	if (crypt_type == CRYPT_TYPE_ENCRYPT)
	{
		p_rsa=PEM_read_bio_RSA_PUBKEY(bio,NULL,NULL,NULL);
	}
	else if (crypt_type == CRYPT_TYPE_DECRYPT)
	{
		p_rsa=PEM_read_bio_RSAPrivateKey(bio,NULL,NULL,NULL);
	}
	BIO_free(bio);
    if(p_rsa==NULL)
	{
		ERR_print_errors_fp(stdout);
        return NULL;
    }
	
	// 在RSA_PKCS1_OAEP_PADDING填充模式下，输出字符串长度比RSA_size()大41
	// flen must be less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING
    rsa_len=RSA_size(p_rsa);
    p_out=(unsigned char *)calloc(rsa_len +1, sizeof(char));
	flen = strlen((char *)source);// 最大长度为86（128-42）
	if (crypt_type == CRYPT_TYPE_ENCRYPT)
	{
		ret = RSA_public_encrypt(flen, source, p_out,p_rsa, RSA_PKCS1_OAEP_PADDING);
	}
	else if (crypt_type == CRYPT_TYPE_DECRYPT)
	{
		ret = RSA_private_decrypt(flen, source, p_out,p_rsa, RSA_PKCS1_OAEP_PADDING);
	}
	RSA_free(p_rsa);
    if(ret < 0)
	{
         return NULL;
    }

    return p_out;
 }

#else

unsigned char* rsa_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	printf("error:no openssl support!\n");
	return NULL;
}

#endif