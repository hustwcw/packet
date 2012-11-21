#ifndef __PACKET_H__
#define __PACKET_H__
#include <stdlib.h>
#include <stdint.h>
#include "type.h"


/**
 * @defgroup packet packet
 * @{
 */


#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

/**
 * 错误定义
 */
enum ERRORNO
{
	SUCCESS=0, /**< 成功 */
	ERROR ,
	MALLOC_ERROR, /**< 内存分配错误 */
	NULL_ERROR ,   
	TYPE_ERROR ,
	SET_TALK_CRT_KEY_ERROR ,
	SET_TALK_CRT_TYPE_ERROR ,
	CMP_TRANSFER_CRT_TYPE_ERROR ,
	SET_TEMP_ERT_KEY_ERROR , 
	CMP_CPS_TYPE_ERROR
};

/**
 * 加密方式xxxxxx
 */
typedef struct {
	char ert_keys[3][ERT_KEY_LEN];                    /**< 加密算法密钥对，0项公钥，1项密钥, 2项其它密钥 */
	char talk_ert_type[ENCRYPTION_LEN];               /**< 当前协商选择的加密方式 */
	char transfer_ert_type[ENCRYPTION_LEN];           /**< 当前数据传输选择的加密方式 */
} ert_t;

/**
 * 压缩方式
 */
typedef struct {
	char cps_type[CPS_TYPE_LEN];                      /**< 当前选择的压缩方式 */
} cps_t;

/**
 * 心跳参数
 */
typedef struct {
	int seconds;                                       /**< 心跳时长 */
	char sponsor[SPONSOR_LEN];                         /**< 心跳控制端可选值server,client */
} heartbeat_t;

/**
 * 客户端相关参数
 */
typedef struct {
	char id[ID_LEN];
	char subject[SUBJECT_LEN];
	char signature[SIGNATURE_LEN];
	char client_id[CLIENT_ID_LEN];                     /**< 客户端ID */
	heartbeat_t heartbeat;                             /**< 心跳相关 */
} cert_t;


/**
 * 加密函数指针
 * 压缩函数指针
 */
typedef unsigned char * (*pkg_ert_hook)(const unsigned char *source, int source_len, int *dest_len, char *encrypt_key, int crypt_type);
typedef int (*pkg_cps_hook)(unsigned char **dest, unsigned long *destLen, const unsigned char *source, unsigned long sourceLen, int plain_len, int type);


/**
 * 包解析器
 */
typedef struct {
	int talk_type;                                  /**< 协商类型,0为协议发起方，1为协议接收方 */
	ert_t curr_ert;                                 /**< 加密方式 */
	cps_t curr_cps;                                 /**< 数据传输压缩方式 */
	cert_t client_cert;                             /**< 客户端证书相关 */
	pkg_ert_hook asym_encrypt_hook;					/**< 非对称加密函数指针 */
	pkg_ert_hook sym_encrypt_hook;					/**< 对称加密函数指针 */
	pkg_cps_hook compress_hook;						/**< 压缩函数指针 */
} packet_parser_t;

/**
 * 初始化一个解析器
 *
 * @param type [in] 0协议发起方，1协议接收方
 * @param id [in] 
 * @param public_key [in] 公钥
 * @param private_key [in] 私钥
 * @param ert_type [in] 加密方式
 * @param cps_type [in] 压缩方式
 *
 * @return 返回解析器指针
 *
 * @note 
 */
packet_parser_t* init_parser(
	int type, 
	const char* id, 
	const char* public_key, 
	const char* private_key, 
	const char* ert_type,
	pkg_ert_hook asym_encrypt_hook,
	pkg_ert_hook sym_encrypt_hook,
	const char* cps_type,
	pkg_cps_hook compress_hook);


/** 
 * 将本地数据组合
 *
 * @param pkg [in] 协商结构
 * @param source [in] 数据源
 * @param source_len [in] 数据源长度
 * @param type [in] 0:协商包， 1：数据包
 * @param dest [out] 组装完成的结果
 *
 * @return 返回解析组合结果：成功或者失败类型
 * @retval 
 *
 * @note 注意使用后主动释放内存
 */
int pkg_data_assemble(
	const packet_parser_t *pkg, 
	const char *source, 
	int source_len, 
	int type,
	char **dest,
	int* dest_len);

/**
 * 将来自网络端的数据解码。
 * 服务器端：解析协商包和数据包
 * 客户端：解析服务器响应的协商包和数据包
 *
 * @param pkg [in][out] 协商结构填充
 * @param source [in] 数据源
 * @param source_len [in] 数据源长度
 * @param type [in] 0:协商包， 1：数据包
 * 
 *
 * @return 解析出来的明文数据包
 */
char* pkg_data_parse( packet_parser_t *pkg, const char* source, int source_len, int type);


#ifdef __cplusplus
}
#endif

/**@}*/

#endif//__PACKET_H__
