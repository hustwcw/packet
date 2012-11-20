#ifndef __CPS_ZLIB_H__
#define __CPS_ZLIB_H__
#include <zlib.h>
#include <stdio.h>
#include "..\type.h"


int zlib_compress (unsigned char **dest, unsigned long *destLen,
	const unsigned char *source, unsigned long sourceLen, int type);


#endif//__CPS_ZLIB_H__
