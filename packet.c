#include <stdio.h>
#include <string.h>
#include "packet.h"
#include "iks/dom.h"
#include "iks/iksemel.h"
#include "encrypt/ert_rsa.h"
#include "encrypt/ert_aes.h"
#include "encrypt/ert_des3.h"
#include "compress/cps_zlib.h"
#include "util.h"


int set_cps_type(const char *src, packet_parser_t *pkg);
int cmp_cps_type(const char *src, packet_parser_t *pkg);
void set_heatbeat(const char *sponsor, const char* seconds, packet_parser_t *pkg);
int set_talk_crt_type(const char* src, packet_parser_t *pkg);
int set_transfer_crt_type(const char* src, packet_parser_t *pkg);
int cmp_transfer_crt_type(const char* src, packet_parser_t *pkg);
int set_talk_crt_public_key(const char* src, packet_parser_t *pkg);
int set_talk_crt_private_key(const char* src, packet_parser_t *pkg);
int set_transfer_crt_key(const char* src, packet_parser_t *pkg);
char* get_transfer_crt_key(const packet_parser_t *pkg);
int set_client_id(const char* src, packet_parser_t *pkg);
int set_cert_id(const char* src, packet_parser_t *pkg);
int set_client_subject(const char* src, packet_parser_t *pkg);
int set_client_signature(const char* src, packet_parser_t *pkg);
int set_talk_type(int type, packet_parser_t *pkg);


/** 
 * 为数据包添加头部
 *
 * @param source [in] 数据源
 * @param src_len [in] 数据源长度。如果为-1则表示source是以\0结尾的字符串。
 * @param plain_len [in] 压缩加密前的数据包长度
 * @param dest_len [out] 输出数据的长度
 *
 * @return 返回添加头部的数据包
 *
 * @note 注意使用后主动释放内存
 */
char *pkg_add_header(const char *source, int src_len, int plain_len, int *dest_len);

/** 
 * 获取数据包的包体，去掉包头。
 * 如果数据包完整，则截取完整部分去掉包头，返回包体，剩余未解析的数据包通过source返回。
 * 如果数据包不完整，则返回NULL。
 *
 * @param source [in] 数据源
 * @param source_len [in] 数据源长度
 * @param plain_body_len [out] 加密压缩前数据包体的长度，用于解压缩数据时分配数据缓冲区
 * @param cipher_body_len [out] 输出数据包体的长度
 * @param remainLen [out] 剩余未解析的数据包片段的长度
 *
 * @return 返回去掉头部的包体
 *
 * @note 注意使用后主动释放内存
 */
char *pkg_get_body(char **source, int source_len, int *plain_body_len, int *cipher_body_len, int *remainLen);

/**
 * 将来自网络端的数据解码。
 * 服务器端：解析协商包和数据包
 * 客户端：解析服务器响应的协商包和数据包
 * 通过回调函数返回解析结果
 *
 * @param pkg [in][out] 协商结构填充
 * @param source [in] 数据源
 * @param source_len [in] 数据源长度
 * @param plain_body_len [in] 数据包在压缩加密前的长度
 * 
 * @return 成功返回0，否则返回错误码
 */
int pkg_data_parse( packet_parser_t *pkg, const char* source, int source_len, int plain_body_len);

// 客户端组装发送给服务器端的协商包。
char* pkg_talk_make(const packet_parser_t *pkg);

// 服务器端组装响应给客户端的协商包
char* pkg_talk_rtn(const packet_parser_t *pkg);

// 
int pkg_talk_parse(packet_parser_t *pkg, const char* xml);

// 对数据包包体进行压缩加密
// 压缩加密后的字符串可能不是以0结尾的，所以需要返回字符串的长度cipher_body_len
char *pkg_compress_encrypt(const packet_parser_t *pkg, const char *source, int source_len, int *cipher_body_len);

// 对收到的数据包包体进行解密解压缩
// 由于返回的是明文数据包所以不需要返回明文数据包的长度（以0结尾的字符串）
char *pkg_uncompress_decrypt(const packet_parser_t *pkg, const char *source, int source_len, int plain_body_len);

void set_heatbeat(const char *sponsor, const char* seconds, packet_parser_t *pkg);



packet_parser_t* init_parser(
	int type, 
	const char* id,
	const char* public_key, 
	const char* private_key, 
	const char* ert_type,
	pkg_ert_hook asym_encrypt_hook,
	pkg_ert_hook sym_encrypt_hook,
	const char* cps_type,
	pkg_cps_hook compress_hook,
	parse_packet_callback callback)
{
	// TODO:加入一些assert断言，判断部分参数是否为空

	packet_parser_t *pkg = (packet_parser_t *)malloc(sizeof(packet_parser_t));
	if(!pkg) return NULL;

	memset(pkg, 0x0, sizeof(packet_parser_t));
	// 设置服务器相关信息
	set_client_id("cliet_id_test_122222", pkg);
	set_client_subject("cliet_subject_test_122222", pkg);
	set_client_signature("cliet_signature_test_122222", pkg);
	set_cert_id("cert_id_test_122222", pkg);
	// 设置加密和压缩相关参数
	set_talk_type(type, pkg);
	set_talk_crt_public_key(public_key, pkg);
	set_talk_crt_private_key(private_key, pkg);
	set_talk_crt_type("RSA_128", pkg);
	pkg->asym_encrypt_hook = asym_encrypt_hook;
	set_transfer_crt_type(ert_type, pkg);
	pkg->sym_encrypt_hook = sym_encrypt_hook;
	// 设置压缩相关参数
	set_cps_type(cps_type, pkg);
	pkg->compress_hook = compress_hook;
	// 回调函数
	pkg->callback = callback;

	return pkg;
}

void flush_parser(packet_parser_t* pkg)
{
	if (pkg->packetBuffer.data)
	{
		free(pkg->packetBuffer.data);
		pkg->packetBuffer.data = NULL;
		pkg->packetBuffer.length = 0;
	}
}

/**
 * 释放包解析器
 */
void free_parser(packet_parser_t* pkg)
{
	if(pkg)
	{
		if (pkg->client_cert.cert_id)
		{
			free(pkg->client_cert.cert_id);
			pkg->client_cert.cert_id = NULL;
		}
		if (pkg->client_cert.client_id)
		{
			free(pkg->client_cert.client_id);
			pkg->client_cert.client_id = NULL;
		}
		if (pkg->client_cert.subject)
		{
			free(pkg->client_cert.subject);
			pkg->client_cert.subject = NULL;
		}
		if (pkg->client_cert.signature)
		{
			free(pkg->client_cert.signature);
			pkg->client_cert.signature = NULL;
		}

		if (pkg->curr_ert.ert_keys[0])
		{
			free(pkg->curr_ert.ert_keys[0]);
			pkg->curr_ert.ert_keys[0] = NULL;
		}
		if (pkg->curr_ert.ert_keys[1])
		{
			free(pkg->curr_ert.ert_keys[1]);
			pkg->curr_ert.ert_keys[1] = NULL;
		}
		if (pkg->curr_ert.ert_keys[2])
		{
			free(pkg->curr_ert.ert_keys[2]);
			pkg->curr_ert.ert_keys[2] = NULL;
		}
		if (pkg->curr_ert.talk_ert_type)
		{
			free(pkg->curr_ert.talk_ert_type);
			pkg->curr_ert.talk_ert_type = NULL;
		}
		if (pkg->curr_ert.transfer_ert_type)
		{
			free(pkg->curr_ert.transfer_ert_type);
			pkg->curr_ert.transfer_ert_type = NULL;
		}

		if (pkg->cps_type)
		{
			free(pkg->cps_type);
			pkg->cps_type = NULL;
		}

		if (pkg->packetBuffer.data)
		{
			free(pkg->packetBuffer.data);
			pkg->packetBuffer.data = NULL;
		}


		free(pkg);
		pkg = NULL;
	}
}


int pkg_data_assemble(  
	const packet_parser_t *pkg, 
	const char *source, 
	int source_len, 
	int type,
	char** dest, 
	int* dest_len)
{
	char *body;

	if (source_len < 0)
	{
		source_len = strlen(source);
	}
	// 组装协商包
	if(0 == type)
	{
		if (pkg->talk_type == 0)
		{
			// 客户端组装请求协商包
			body = pkg_talk_make(pkg);
		}
		else if (pkg->talk_type == 1)
		{
			// 服务器端组装响应协商包
			body = pkg_talk_rtn(pkg);
		}
		*dest_len = strlen(body);
	}
	// 组装数据包
	else
	{
		// 服务器端和客户端组装数据包是一样的，都是调用加密压缩函数根据当前pkg的加密压缩方式对数据源source进行加密和压缩
		body = pkg_compress_encrypt(pkg, source, source_len, dest_len);
	}
	
	if(NULL == body)
	{
		return NULL_ERROR;
	}
	*dest = pkg_add_header(body, *dest_len, source_len, dest_len);
	free(body);

	return SUCCESS;
}


int parse_packet(packet_parser_t*pkg, char *source, int sourceLen)
{
	char *tempFragment;
	char * packet;
	int cipher_body_len;
	int plain_body_len;

	if (sourceLen < 0)
	{
		sourceLen = strlen(source);
	}
	// 首先做数据拼接，将新到来的数据包片段拼接到未处理的数据包片段后面。
	tempFragment = pkg->packetBuffer.data;
	pkg->packetBuffer.data = (char *)malloc(pkg->packetBuffer.length + sourceLen);
	memcpy(pkg->packetBuffer.data, tempFragment, pkg->packetBuffer.length);
	memcpy(pkg->packetBuffer.data+pkg->packetBuffer.length, source, sourceLen);
	pkg->packetBuffer.length += sourceLen;
	if (tempFragment)
	{
		free(tempFragment);
	}

	// 对拼接后的数据包进行解析，判断是否完整
	if (packet = pkg_get_body(&pkg->packetBuffer.data, pkg->packetBuffer.length, &plain_body_len, &cipher_body_len, &(pkg->packetBuffer.length)))
	{
		// 数据包完整，进行解析
		return pkg_data_parse(pkg, packet, cipher_body_len, plain_body_len);
	}
}
// 
int pkg_data_parse( packet_parser_t *pkg, const char* source, int source_len, int plain_body_len)
{
	char *parseed_body = NULL; // 解析出来的包体
	int type = 0;
	int result;
	// TODO：根据包体是否经过加密判断是数据包还是协商包 
	iks *x =	iks_tree (source, 0, &result);

	// 解析协商包
	if (x)
	{
		if (pkg->talk_type == 0)
		{
			// 客户端解析服务器端响应的协商包，从中解析出以后通信使用的临时密钥并解密后填充到pkg中
			return pkg_talk_parse(pkg, source);
		}
		else if (pkg->talk_type == 1)
		{
			// 服务器端解析客户端发来的协商包请求
			return pkg_talk_parse(pkg, source);
		}
	}
	// 解析数据包
	else
	{
		// 是数据包,返回解析出来的明文数据包
		parseed_body = pkg_uncompress_decrypt(pkg, source, source_len, plain_body_len);
		pkg->callback(parseed_body);
		return SUCCESS;
	}
}

// 对数据包进行加密和压缩
char *pkg_compress_encrypt(const packet_parser_t *pkg, const char *source, int source_len, int *cipher_body_len)
{
	char *encrypt_string;
	char *compress_string = NULL;
	uLongf compress_dest_len;

	if (source_len < 0)
	{
		source_len = strlen(source);
	}
	
	// 先对数据源进行压缩
	if (pkg->compress_hook == NULL)
	{
		zlib_compress((unsigned char **)(&compress_string), &compress_dest_len, (unsigned char *)source, source_len, 0, COMPRESS_TYPE);
	}
	else
	{
		pkg->compress_hook((unsigned char **)(&compress_string), &compress_dest_len, (unsigned char *)source, source_len, 0, COMPRESS_TYPE);
	}

	printf("source len:%d\tcompress len:%d\n", source_len, compress_dest_len);
	// 再对数据进行加密
	if (strcmp(pkg->curr_ert.transfer_ert_type, ENCRYPT_AES_128) == 0)
	{
		if (pkg->sym_encrypt_hook == NULL)
		{
			encrypt_string = (char *)aes_encrypt((unsigned char *)compress_string, compress_dest_len, cipher_body_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_ENCRYPT);
		}
		else
		{
			encrypt_string = (char *)aes_encrypt((unsigned char *)compress_string, compress_dest_len, cipher_body_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_ENCRYPT);
		}
	}
	else if (strcmp(pkg->curr_ert.transfer_ert_type, ENCRYPT_DES3_128) == 0)
	{
		if (pkg->sym_encrypt_hook == NULL)
		{
			encrypt_string = (char *)des3_encrypt((unsigned char *)compress_string, compress_dest_len, cipher_body_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_ENCRYPT);
		}
		else
		{
			encrypt_string = (char *)pkg->sym_encrypt_hook((unsigned char *)compress_string, compress_dest_len, cipher_body_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_ENCRYPT);
		}
	}

	if (compress_string)
	{
		free(compress_string);
	}

	return encrypt_string;
}

char *pkg_uncompress_decrypt(const packet_parser_t *pkg, const char *source, int source_len, int plain_body_len)
{
	char *encrypt_string;
	char *compress_string = NULL;
	int decrypt_dest_len;
	uLongf uncompress_dest_len;

	// 先对数据源进行解密
		if (strcmp(pkg->curr_ert.transfer_ert_type, ENCRYPT_AES_128) == 0)
		{
			if (pkg->sym_encrypt_hook == NULL)
			{
				encrypt_string = (char *)aes_encrypt((unsigned char *)source, source_len, &decrypt_dest_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_DECRYPT);
			}
			else
			{
				encrypt_string = (char *)pkg->sym_encrypt_hook((unsigned char *)source, source_len, &decrypt_dest_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_DECRYPT);
			}
		}
		else if (strcmp(pkg->curr_ert.transfer_ert_type, ENCRYPT_DES3_128) == 0)
		{
			if (pkg->sym_encrypt_hook == NULL)
			{
				encrypt_string = (char *)des3_encrypt((unsigned char *)source, source_len, &decrypt_dest_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_DECRYPT);
			}
			else
			{
				encrypt_string = (char *)pkg->sym_encrypt_hook((unsigned char *)source, source_len, &decrypt_dest_len, (char *)pkg->curr_ert.ert_keys[2], CRYPT_TYPE_DECRYPT);
			}
		}
	// 再对数据进行解压缩
	if (pkg->compress_hook == NULL)
	{
		zlib_compress((unsigned char **)(&compress_string), &uncompress_dest_len, (unsigned char *)encrypt_string, decrypt_dest_len, plain_body_len, UNCOMPRESS_TYPE);
	}
	else
	{
		pkg->compress_hook((unsigned char **)(&compress_string), &uncompress_dest_len, (unsigned char *)encrypt_string, decrypt_dest_len, plain_body_len, UNCOMPRESS_TYPE);
	}

	if (encrypt_string)
	{
		free(encrypt_string);
	}

	return compress_string;
}

/// 客户端组装发给服务器端的协商包。
char* pkg_talk_make(const packet_parser_t *pkg)
{
	char *r;
	iks *x, *tmp;
	x = iks_new ("connection");
	if(NULL == x) return NULL;

	iks_insert_attrib(x, "xmlns", TALK_XMLNS);
	iks_insert_attrib(x, "type", "create");
	tmp = iks_insert(x, "client-id");
	if(NULL != tmp) {
		iks_insert_cdata(tmp, pkg->client_cert.client_id, 0);
	}
	
	tmp = iks_insert(x, "public-key");
	if(NULL != tmp) {
		iks_insert_cdata(tmp, pkg->curr_ert.ert_keys[0], 0);
		iks_insert_attrib(tmp, "type", pkg->curr_ert.talk_ert_type);
	}

	if(0 != strlen(pkg->curr_ert.talk_ert_type)){
		tmp = iks_insert(x, "encryption");
		iks_insert_cdata(iks_insert(tmp,"allow"), pkg->curr_ert.transfer_ert_type, 0);
	}
	
	if(0 != strlen(pkg->cps_type)){
		tmp = iks_insert(x, "compression");
		iks_insert_cdata(iks_insert(tmp,"allow"), pkg->cps_type, 0);
	}

	if( pkg->client_cert.signature[0] != 0 ){
		tmp = iks_insert(x, "certificate");
		iks_insert_attrib(tmp, "id", pkg->client_cert.cert_id);
		iks_insert_cdata(iks_insert(tmp, "subject"), pkg->client_cert.subject, 0);
		iks_insert_cdata(iks_insert(tmp, "signature"), pkg->client_cert.signature, 0);
	}

	r = iks_string(NULL, x);
	iks_delete(x);
	return r;
}

// 服务器端组装发给客户端的协商包
char* pkg_talk_rtn(const packet_parser_t *pkg)
{
	char *r;
	unsigned char *encrypted_key;// 使用公钥加密过的临时密钥
	char *output;
	iks *x, *tmp;
	int dest_len;

	x = iks_new ("connection");
	if(NULL == x) return NULL;

	iks_insert_attrib(x, "xmlns", TALK_XMLNS);
	iks_insert_attrib(x, "type", "result");
	tmp = iks_insert(x, "encryption");
	iks_insert_attrib(tmp, "type", pkg->curr_ert.transfer_ert_type);
	// 使用公钥对临时密钥进行加密
	if (pkg->asym_encrypt_hook == NULL)
	{
		encrypted_key = rsa_encrypt((unsigned char *)get_transfer_crt_key(pkg), strlen(get_transfer_crt_key(pkg)), &dest_len, (char *)(pkg->curr_ert.ert_keys[0]), CRYPT_TYPE_ENCRYPT);
	}
	else
	{
		encrypted_key = pkg->asym_encrypt_hook((unsigned char *)get_transfer_crt_key(pkg), strlen(get_transfer_crt_key(pkg)), &dest_len, (char *)(pkg->curr_ert.ert_keys[0]), CRYPT_TYPE_ENCRYPT);
	}
	output = (char *)calloc(strlen((char *)encrypted_key)*2+1, 1);
	byte2hex(encrypted_key, strlen((char *)encrypted_key), output);
	iks_insert_cdata(tmp, output, 0);
	free(output);

	iks_insert_cdata(iks_insert(x, "compression"), pkg->cps_type, 0);
	iks_insert_attrib(iks_insert(x, "heartbeat"), "sponsor", "server");
	iks_insert_attrib(iks_insert(x, "heartbeat"), "seconds", "60");

	r = iks_string(NULL, x);
	iks_delete(x);
	return r;
}

// 客户端解析服务器响应的协商包，从协商包中解析出临时密钥，并使用自己的私钥进行解密
// 服务器端解析客户端发来的协商包，并填充服务器包解析器
int pkg_talk_parse(packet_parser_t *pkg, const char* xml)
{
	iks *x, *e, *c;
	int result=0;
	int i = 0;
	int dest_len;

	if(NULL==xml) return NULL_ERROR;

	x =	iks_tree (xml, 0, &result);
	if(!x) return NULL_ERROR;
	if(result != IKS_OK)
	{
		iks_free(x);
		return IKS_BADXML;
	}

	if(0 == iks_strcmp("connection",iks_name(x)))
	{
		char* tmp = NULL;
		char *tempkey;
		char *output;

		tmp = iks_find_attrib(x, "type");
		if(NULL != tmp){
			if(strcmp(tmp, "create")==0)
				set_talk_type(1, pkg); //说明为服务端
			else
				set_talk_type(0, pkg); //说明为客户端
		}

		if(1 == pkg->talk_type)
		{
			//说明本端为服务端
			tmp = iks_find_cdata(x, "client-id");
			set_client_id(tmp, pkg);

			tmp = iks_find_cdata(x, "public-key");
			if(SUCCESS != set_talk_crt_public_key(tmp, pkg))
				return SET_TALK_CRT_KEY_ERROR;

			tmp = iks_find_attrib(iks_find(x,"public-key"), "type");
			if(SUCCESS != set_talk_crt_type(tmp, pkg))
				return SET_TALK_CRT_TYPE_ERROR;

			e = iks_find(x,"encryption");
			while( e ){
				tmp = iks_find_cdata(e, "allow");
				if(SUCCESS == set_transfer_crt_type(tmp, pkg)) break;
				e = iks_next(e);
			}
			// 服务器端设置传输数据使用的临时密钥
			set_transfer_crt_key(TRANSFERKEY, pkg);

			c = iks_find(x,"compression");
			while( c ){
				tmp = iks_find_cdata(c, "allow");
				if(SUCCESS == set_cps_type(tmp, pkg)) break;
				c = iks_next(c);
			}
		}
		else if(0 == pkg->talk_type)
		{
			// 说明本端为客户端
			tempkey = iks_find_cdata(x,"encryption");
			output = (char *)calloc(strlen(tempkey)/2+1, 1);
			hex2byte(tempkey, strlen(tempkey), (unsigned char *)output);
			if (pkg->asym_encrypt_hook == NULL)
			{
				tempkey = (char *)rsa_encrypt((unsigned char *)output, strlen(output), &dest_len, pkg->curr_ert.ert_keys[1], CRYPT_TYPE_DECRYPT);
			}
			else
			{
				tempkey = (char *)pkg->asym_encrypt_hook((unsigned char *)output, strlen(output), &dest_len, pkg->curr_ert.ert_keys[1], CRYPT_TYPE_DECRYPT);
			}
			free(output);

			if( SUCCESS != set_transfer_crt_key(tempkey, pkg))
				return SET_TRANSFER_ERT_KEY_ERROR;
			if( SUCCESS != cmp_transfer_crt_type(iks_find_attrib(iks_find(x, "encryption"), "type"), pkg) )
				return CMP_TRANSFER_CRT_TYPE_ERROR;
			if( SUCCESS != cmp_cps_type(iks_find_cdata(x, "compression"), pkg) )
				return CMP_CPS_TYPE_ERROR;
			set_heatbeat(iks_find_attrib(iks_find(x, "heartbeat"), "sponsor"), 
						iks_find_attrib(iks_find(x, "heartbeat"), "seconds"), pkg);
		}	
	} 
	
	//iks_parser_delete (p);
	iks_delete(x);
	return SUCCESS;
}

// 为数据包添加包头
char *pkg_add_header(const char *src, int src_len, int plain_len, int *dest_len)
{
	char *dest;
	if(NULL == src) 
		return NULL;

	if(src_len < 0)
		src_len = strlen(src);
	*dest_len = src_len + 1 + 1 + 4 + 4;
	dest = (char*)malloc(*dest_len);
	memcpy(dest, "C", 1);
	memcpy(dest+1, "1", 1);
	// 包长度数字直接填充，不需要转换为字符串
	*((int *)(dest+2)) = *dest_len;
	// 压缩前的数据包长度
	*((int *)(dest+6)) = plain_len;
	memcpy(dest+10, src, src_len);

	return dest;
}

// 返回包体。
char *pkg_get_body(char **source, int source_len, int *plain_body_len, int *cipher_body_len, int *remainLen)
{
	int packet_len;
	char *cipher_body;
	char *remainPacket;

	if(NULL == *source || NULL == plain_body_len || NULL == cipher_body_len
		|| NULL == remainLen || source_len < 10)
	{
		return NULL;
	}

	packet_len = *(int *)(*source + 2);
	if (packet_len <= source_len)
	{
		*cipher_body_len = packet_len - 10;
		*plain_body_len = *(int *)(*source + 6);
		*remainLen = source_len - packet_len;
		cipher_body = (char *)calloc(*cipher_body_len + 1, sizeof(char));
		memcpy(cipher_body, (*source)+10, *cipher_body_len);
		
		// 剩余数据包处理
		remainPacket = (char *)malloc(*remainLen);
		memcpy(remainPacket, *source + packet_len, *remainLen);
		free(*source);
		*source = remainPacket;

		return cipher_body;
	}


	return NULL;
}


int set_client_id(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->client_cert.client_id = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->client_cert.client_id, src, strlen(src));
	pkg->client_cert.client_id[strlen(src)] = '\0';

	return SUCCESS;
}

int set_cert_id(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->client_cert.cert_id = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->client_cert.cert_id, src, strlen(src));
	pkg->client_cert.cert_id[strlen(src)] = '\0';

	return SUCCESS;
}

int set_client_subject(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->client_cert.subject = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->client_cert.subject, src, strlen(src));
	pkg->client_cert.subject[strlen(src)] = '\0';

	return SUCCESS;
}

int set_client_signature(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->client_cert.signature = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->client_cert.signature, src, strlen(src));
	pkg->client_cert.signature[strlen(src)] = '\0';

	return SUCCESS;
}

int set_talk_type(int type, packet_parser_t *pkg)
{
	if(type>1 || !pkg) return NULL_ERROR;

	pkg->talk_type = type;

	return SUCCESS;
}

// 设置协商阶段的加密方式
int set_talk_crt_type(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->curr_ert.talk_ert_type = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->curr_ert.talk_ert_type, src, strlen(src));
	pkg->curr_ert.talk_ert_type[strlen(src)] = '\0';

	return SUCCESS;
}

int set_talk_crt_public_key(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->curr_ert.ert_keys[0] = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->curr_ert.ert_keys[0], src, strlen(src));
	pkg->curr_ert.ert_keys[0][strlen(src)] = '\0';

	return SUCCESS;
}

int set_talk_crt_private_key(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->curr_ert.ert_keys[1] = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->curr_ert.ert_keys[1], src, strlen(src));
	pkg->curr_ert.ert_keys[1][strlen(src)] = '\0';

	return SUCCESS;
}

// 设置服务器响应的以后使用的对称加密方式
int set_transfer_crt_type(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->curr_ert.transfer_ert_type = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->curr_ert.transfer_ert_type, src, strlen(src));
	pkg->curr_ert.transfer_ert_type[strlen(src)] = '\0';

	return SUCCESS;
}

// 设置压缩方式
int set_cps_type(const char *src, packet_parser_t *pkg)
{
	if(NULL == src || !pkg) return NULL_ERROR;

	pkg->cps_type = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->cps_type, src, strlen(src));
	pkg->cps_type[strlen(src)] = '\0';

	return SUCCESS;
}

// 比较压缩方式
int cmp_cps_type(const char *src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	if(0 != strcmp(pkg->cps_type, src))
		return CMP_CPS_TYPE_ERROR;

	return SUCCESS;
}

int cmp_transfer_crt_type(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	if(0 != strcmp(pkg->curr_ert.transfer_ert_type , src))
		return CMP_TRANSFER_CRT_TYPE_ERROR ;
		
	return SUCCESS;
}

int set_transfer_crt_key(const char* src, packet_parser_t *pkg)
{
	if(!src || !pkg) return NULL_ERROR;

	pkg->curr_ert.ert_keys[2] = (char *)malloc(strlen(src) + 1);
	strncpy(pkg->curr_ert.ert_keys[2], src, strlen(src));
	pkg->curr_ert.ert_keys[2][strlen(src)] = '\0';

	return SUCCESS;
}
// 心跳
void set_heatbeat(const char *sponsor, const char* seconds, packet_parser_t *pkg)
{
	if(NULL == seconds || 0x0 == seconds[0]) 
		pkg->client_cert.heartbeat.seconds = HEARTBEAT;
	else
		pkg->client_cert.heartbeat.seconds = atoi(seconds);

	if(NULL == sponsor || 0x0 == sponsor[0]) 
		strncpy(pkg->client_cert.heartbeat.sponsor , 
		"client" , sizeof(pkg->client_cert.heartbeat.sponsor));
	else
		strncpy(pkg->client_cert.heartbeat.sponsor , 
		sponsor , sizeof(pkg->client_cert.heartbeat.sponsor));
}


char* get_transfer_crt_key(const packet_parser_t *pkg)
{
	if(!pkg) return NULL;

	return (char *)pkg->curr_ert.ert_keys[2];
}

