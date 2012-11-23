#include <stdio.h>
#include "ert_aes.h"
#include <openssl/aes.h>

#ifdef __OPENSSL_SUPPORT 

unsigned char* aes_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char *dest;
    //unsigned int dest_len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;

	// set the encryption length
	if (source_len < 0)
	{
		source_len = strlen((const char *)source);
	}
    if ((source_len + 1) % AES_BLOCK_SIZE == 0)
	{
        *dest_len = source_len + 1;
    }
	else
	{
        *dest_len = ((source_len + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }

	// Generate AES 128-bit key
    for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
        key[i] = 32 + i;
    }
    // Set encryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i)
	{
        iv[i] = 0;
    }
 
    // alloc encrypt_string
    dest = (unsigned char*)malloc(*dest_len);
    if (dest == NULL)
	{
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }
 
	if (crypt_type == CRYPT_TYPE_ENCRYPT)
	{
		if (AES_set_encrypt_key(key, 128, &aes) < 0)
		{
			free(dest);
			fprintf(stderr, "Unable to set encryption key in AES\n");
			exit(-1);
		}
		// encrypt (iv will change)
		AES_cbc_encrypt(source, dest, *dest_len, &aes, iv, AES_ENCRYPT);
	}
	else if (crypt_type == CRYPT_TYPE_DECRYPT)
	{
		if (AES_set_decrypt_key(key, 128, &aes) < 0)
		{
			free(dest);
			fprintf(stderr, "Unable to set decryption key in AES\n");
			exit(-1);
		}
		// decrypt
		AES_cbc_encrypt(source, dest, *dest_len, &aes, iv, AES_DECRYPT);
	}
 
    return dest;
}


#else

unsigned char* aes_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type)
{
	printf("error:no openssl support!\n");
	return NULL;
}

#endif
