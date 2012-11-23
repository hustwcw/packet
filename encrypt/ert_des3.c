#include "ert_des3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#ifdef __OPENSSL_SUPPORT

unsigned char* des3_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	DES_cblock key;
	DES_key_schedule ks1, ks2, ks3;
    unsigned char *output;
	DES_cblock ivec;
	int error;
	char block_key[9]={0};

	// 使用encrypt_key字符串生成3个schedule key
	memcpy(block_key, encrypt_key, 8);
	DES_string_to_key(block_key, &key);
    error = DES_set_key_checked(&key, &ks1);
	memcpy(block_key, encrypt_key+8, 8);
	DES_string_to_key(block_key, &key);
	DES_set_key_checked(&key, &ks2);
	memcpy(block_key, encrypt_key+16, 8);
	DES_string_to_key(block_key, &key);
	DES_set_key_checked(&key, &ks3);

	if (source_len < 0)
	{
		source_len = strlen((char *)source);
	}
	*dest_len = (source_len/8 + 1)*8;
	output = (unsigned char *)calloc(*dest_len, sizeof(char));
	
    memset((char*)&ivec, 0, sizeof(ivec));//ivec清0
	// cbc模式的des3
	if (crypt_type == CRYPT_TYPE_ENCRYPT)
	{
		DES_ede3_cbc_encrypt(source, output, source_len, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);
	}
	else if (crypt_type == CRYPT_TYPE_DECRYPT)
	{
		DES_ede3_cbc_encrypt(source, output, source_len, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);
	}
	return output;
}

#else

unsigned char* des3_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	printf("error:no openssl support!\n");
	return NULL;
}

#endif