#ifndef __ERT_RSA_H__
#define __ERT_RSA_H__
#include <stdlib.h>
#include <stdint.h>
#include "../type.h"



#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

unsigned char* rsa_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type);//º”√‹Ω‚√‹

#ifdef __cplusplus
}
#endif

#endif//__ERT_RSA_H__
