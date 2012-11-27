#include <stdio.h>
#include <string.h>
#include "packet.h"
#include "encrypt/ert_aes.h"
#include "encrypt/ert_des3.h"
#include "encrypt/ert_rsa.h"
#include "compress/cps_zlib.h"
#include "type.h"


//#define _CRTDBG_MAP_ALLOC
//#include <stdlib.h>
//#include <crtdbg.h>

int processPacket(char *packet);

int main(int argc, char** argv)
{
	int i=0;
	char *dest=NULL;
	int dest_len;
	packet_parser_t *client , *server = NULL;
	char *data_packet = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<connection xmlns=\"http://www.ecplive.com/protocol/connection\" type=\"create\">\
<client-id>{UUID}</client-id><public-key type=\"RSA-128\">{16进制字符串}</public-key>\
<encryption><allow>AES-128</allow><allow>DES-128</allow><allow>3DES-128</allow></encryption>\
<compression><allow>none</allow><allow>zlib</allow></compression><certificate id=\"100\">\
<subject>iPhone 1.5.0.0</subject><signature>0B0C12345</signature></certificate></connection>";

	//_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
	// 客户端初始化
	client = init_parser(0, "123456", PUBLICKEY, PRIVATEKEY, ENCRYPT_AES_128, NULL, NULL, COMPRESS_ZLIB, NULL, processPacket);
	// 客户端组装协商包
	pkg_data_assemble(client, NULL, 0, 0, &dest, &dest_len);
	printf("client talk request:\n");
	for(i=0; i<dest_len; ++i)
		printf("%c", dest[i]);
	printf("\n\n");

	//服务端解析协商包并填充服务器的包解析器
	server = init_parser(1, "121243", NULL, NULL, NULL, NULL, NULL, NULL, NULL,processPacket);
	parse_packet(server, dest, dest_len);
	free(dest);dest = NULL;
	dest_len = 0;

	// 根据解析结果生成的服务器包解析器生成服务器对于协商包的响应包
	pkg_data_assemble(server, NULL, 0, 0, &dest, &dest_len);
	printf("server talk response:\n");
		for(i=0; i<dest_len; ++i)
			printf("%c", dest[i]);
	printf("\n\n");

	// 客户端解析服务器端的响应,修改自己的包解析器中保存的传输数据使用的临时密钥
	parse_packet(client, dest, dest_len);
	printf("key:%s\n",client->curr_ert.ert_keys[2]);
	free(dest);

	// 客户端使用临时密钥加密自己的数据，与服务器通信
	dest_len = 0;
	pkg_data_assemble(client, data_packet, -1, 1, &dest, &dest_len);
	printf("client data packet:\n");
	for(i=0; i<dest_len; ++i)
		printf("%c", dest[i]);
	printf("\n\n\n");

	//服务端组回应协商包
	parse_packet(server, dest, dest_len);
	free(dest);

	free_parser(client);
	free_parser(server);
	//_CrtDumpMemoryLeaks();
	return 0;
}

int processPacket(char *packet)
{
	printf("%s\n", packet);
	return SUCCESS;
}

