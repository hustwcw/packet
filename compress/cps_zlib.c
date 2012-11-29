#include "cps_zlib.h"
#include "stdlib.h"

#ifdef __ZLIB_SUPPORT

int zlib_compress (unsigned char **dest, unsigned long *dest_len,
	const unsigned char *source, unsigned long source_len, int plain_len, int type)
{
	int err = 0;
	if (type == COMPRESS_TYPE)
	{
 		*dest_len = compressBound(source_len);
		*dest = (unsigned char *)malloc(*dest_len+1);
		err = compress2(*dest, dest_len, source, source_len,1);
		if (err != Z_OK)
			fprintf(stderr, "%s error: %d\n", "compress", err);
		(*dest)[*dest_len]=0x0;
	}
	else if (type == UNCOMPRESS_TYPE)
	{
		*dest_len = plain_len; // 暂时的长度
		*dest = (unsigned char *)malloc(*dest_len+1);
		err = uncompress(*dest, dest_len, source, source_len);
		if (err != Z_OK)
			fprintf(stderr, "%s error: %d\n", "uncompress", err); 
		(*dest)[*dest_len]=0x0;
	}
	
	return err;
}

#else

int zlib_compress (unsigned char **dest, unsigned long *dest_len,
	const unsigned char *source, unsigned long source_len, int plain_len, int type)
{
	printf("error:no zlib support!\n");
	return NULL;
}

#endif
