#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


unsigned char to_hex(const unsigned char x)
{
	return x > 9 ? x + 55: x + 48;
}

void byte2hex( const unsigned char* in, int len, char* out )
{
	int i;
	int j;
	for (i=0, j=0; i<len; ++i, j+=2){
		out[j] = to_hex( (unsigned char)in[i] >> 4 );
		out[j+1] = to_hex( (unsigned char)in[i] % 16);
	}
}

unsigned char from_hex(const unsigned char x)
{
	return isdigit(x) ? x-'0' : x-'A'+10;
}

void hex2byte(const char* in, int len, unsigned char* out)
{
	int i;
	int j;
	for(i=0, j=0; i<len; i+=2,++j){
		out[j] = from_hex(in[i])<<4;
		out[j] |= from_hex(in[i+1]);
	}
}