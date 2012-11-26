#ifndef __TYPE_H__
#define __TYPE_H__

#ifdef __cplusplus
#include <cstddef>	/* size_t for C++ */
extern "C" {
#endif

#define _IO
#define _IN 
#define _OUT


#define __OPENSSL_SUPPORT
#define __ZLIB_SUPPORT


/* length */
#define CLIENT_ID_LEN      128     //客户端ID长度
#define CLIENT_TYPE_LEN     64     //客户端类型长度
#define EPT_TYPE_NUM        24     //加密种类数量
#define CMS_TYPE_NUM        24     //压缩类数量
#define TALK_TYPE_LEN       20     //协商类型
#define METHOD_LEN          20     //加密及压缩方法数量
#define ERT_KEY_LEN        1024     //密钥长度
#define ID_LEN              64     //唯一消息ID
#define SUBJECT_LEN         64     //手机型号信息
#define SIGNATURE_LEN      128     //证书相关
#define SPONSOR_LEN         10     //心跳控制端长度

#define HEARTBEAT           120     //默认心跳周期

/* xmlns */
#define TALK_XMLNS  "http://www.ecplive.com/protocol/connection"




// 加密解密
#define CRYPT_TYPE_ENCRYPT 1
#define	CRYPT_TYPE_DECRYPT 0
// 压缩解压缩
#define COMPRESS_TYPE		1
#define UNCOMPRESS_TYPE		0


#define PRIVATEKEYPATH "private.key"
#define PUBLICKEYPATH	"public.key"

#define PRIVATEKEY	"-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQCgkUZA2w+mfYo+dnXwcKx4B+AmF5zVoBKl3wVLVnxJ8FiRCCeR\n\
pxx+DcONKTyKsi8+CvcTuHuWTL8ooeWbBAq7mArs+liGhcwNmTaYFL1yVnbH9tQL\n\
t9PhAwUeD1epILnS859GKj9ft+WPgPN6oW5whKu0mX6HUk4Yematr7e0cwIDAQAB\n\
AoGAI+SVqcXOV89UaeYdMyRcyXApQRqiKnbf9EhIbLDmk7iwc6s4/Sw4CE2XWyTO\n\
rcprGRlmZfglWFHLoY+fPenHZBFBAxwBiy9SZatOPFA3OKIY6BfUox7A5yVSCo4F\n\
oO/+/yVTRygRmnFJzrJDKgqr7hYKtW2V207hF4gdxttfw3ECQQDSrDpyXt8GF/DY\n\
0nBJETbSqI3NXND/AmwrKiFXVwIgqd8S6gP9NcqmhnRkLLrzVe3ADvicwLIuFLaS\n\
JXJUNLPlAkEAwx1EUdzwxXf7qQMb+ZqIlsGApA2q2S4tZ2eEvQgvPLwOOTnYiX+q\n\
Vgqiia3lFAHH5bHjOsnE+3eDpYy0S5BxdwJARKMoR6rxLqMOLRYizyt0mR2hVY8v\n\
6GV5qHaJdlM6tjmiHB9yPUURST/1G84W+sC8PR6jkS6W3ryQ3vykSxsAoQJBAJM/\n\
XBb3yZENOpRTb2JQ2HIFeILWebBLZCKcghVyvst0FLvlRuCFw1QJ1J5Y6P/PVD+p\n\
nxX3vbwVdvmSFWLNkIMCQBewr4dlkBAaYymx/Tq7lIlKcgXviuZVNW6u0vlGUBRs\n\
2AvLBNynL8ObYZy9gnLcGDdzI4v75TzluTiK+22i5dc=\n\
-----END RSA PRIVATE KEY-----\n"
#define PUBLICKEY	"-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgkUZA2w+mfYo+dnXwcKx4B+Am\n\
F5zVoBKl3wVLVnxJ8FiRCCeRpxx+DcONKTyKsi8+CvcTuHuWTL8ooeWbBAq7mArs\n\
+liGhcwNmTaYFL1yVnbH9tQLt9PhAwUeD1epILnS859GKj9ft+WPgPN6oW5whKu0\n\
mX6HUk4Yematr7e0cwIDAQAB\n\
-----END PUBLIC KEY-----\n"
#define	TRANSFERKEY	"transferkeytransmysymkey"


// 对称加密方式
#define ENCRYPT_DES3_128	"3DES-128"
#define ENCRYPT_AES_128		"AES-128"

// 压缩方式
#define	COMPRESS_ZLIB		"zlib"



#ifdef __cplusplus
}
#endif

#endif
