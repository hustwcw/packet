#include "ert_des3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#ifdef __OPENSSL_SUPPORT

unsigned char* des3_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	DES_cblock key;
	DES_key_schedule schedule;
    unsigned char *output;
	DES_cblock ivec;

	DES_string_to_key(encrypt_key, &key);
    DES_set_key_checked(&key, &schedule);
	if (source_len < 0)
	{
		source_len = strlen((char *)source);
	}
	output = (unsigned char *)calloc(source_len + 1, sizeof(char));
	
    memset((char*)&ivec, 0, sizeof(ivec));//ivec清0
	// cfb模式的des3
	if (crypt_type == CRYPT_TYPE_ENCRYPT)
	{
		DES_ede3_cfb64_encrypt(source, output, source_len, &schedule, &schedule, &schedule, &ivec, dest_len, DES_ENCRYPT);
	}
	else if (crypt_type == CRYPT_TYPE_DECRYPT)
	{
		DES_ede3_cfb64_encrypt(source, output, source_len, &schedule, &schedule, &schedule, &ivec, dest_len, DES_DECRYPT);
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