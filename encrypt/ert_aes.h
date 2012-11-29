﻿#ifndef __ERT_AES_H__
#define __ERT_AES_H__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../type.h"


#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

unsigned char* aes_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type);//加密解密

#ifdef __cplusplus
}
#endif

#endif//__ERT_AES_H__
