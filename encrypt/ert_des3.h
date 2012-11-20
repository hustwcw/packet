#ifndef __ERT_DES3_H__
#define __ERT_DES3_H__
#include <stdio.h>
#include "../type.h"

#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

unsigned char* des3_encrypt(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int encrypt_type);//º”√‹

#ifdef __cplusplus
}
#endif

#endif//__ERT_DES3_H__
