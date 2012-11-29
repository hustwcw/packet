#ifndef __CPS_ZLIB_H__
#define __CPS_ZLIB_H__
#include <zlib.h>
#include <stdio.h>
#include "../type.h"

#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

int zlib_compress (unsigned char **dest, unsigned long *destLen,
	const unsigned char *source, unsigned long sourceLen, int plain_len, int type);

#ifdef __cplusplus
}
#endif

#endif//__CPS_ZLIB_H__
