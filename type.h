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
#define CLIENT_ID_LEN      128     //�ͻ���ID����
#define CLIENT_TYPE_LEN     64     //�ͻ������ͳ���
#define EPT_TYPE_NUM        24     //������������
#define ENCRYPTION_LEN      64     //�������Ƴ���
#define CPS_TYPE_LEN        64     //ѹ�����Ƴ���
#define CMS_TYPE_NUM        24     //ѹ��������
#define COMPRESSION_LEN     64     //ѹ�����Ƴ���
#define TALK_TYPE_LEN       20     //Э������
#define METHOD_LEN          20     //���ܼ�ѹ����������
#define ERT_KEY_LEN        1024     //��Կ����
#define ID_LEN              64     //Ψһ��ϢID
#define SUBJECT_LEN         64     //�ֻ��ͺ���Ϣ
#define SIGNATURE_LEN      128     //֤�����
#define SPONSOR_LEN         10     //�������ƶ˳���

#define HEARTBEAT           120     //Ĭ����������

/* xmlns */
#define TALK_XMLNS  "http://www.ecplive.com/protocol/connection"




// ���ܽ���
#define CRYPT_TYPE_ENCRYPT 1
#define	CRYPT_TYPE_DECRYPT 0
// ѹ����ѹ��
#define COMPRESS_TYPE		1
#define UNCOMPRESS_TYPE		0


#define PRIVATEKEYPATH "private.key"
#define PUBLICKEYPATH	"public.key"

#define PRIVATEKEY			"-----BEGIN RSA PRIVATE KEY-----\n\
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
#define PUBLICKEY			"-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgkUZA2w+mfYo+dnXwcKx4B+Am\n\
F5zVoBKl3wVLVnxJ8FiRCCeRpxx+DcONKTyKsi8+CvcTuHuWTL8ooeWbBAq7mArs\n\
+liGhcwNmTaYFL1yVnbH9tQLt9PhAwUeD1epILnS859GKj9ft+WPgPN6oW5whKu0\n\
mX6HUk4Yematr7e0cwIDAQAB\n\
-----END PUBLIC KEY-----\n"
#define	SERVERPUBLICKEY		"-----BEGIN RSA PRIVATE KEY-----\n\
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


// �ԳƼ��ܷ�ʽ
#define ENCRYPT_DES3_128	"3DES-128"
#define ENCRYPT_AES_128		"AES-128"

// ѹ����ʽ
#define	COMPRESS_ZLIB		"zlib"



#ifdef __cplusplus
}
#endif

#endif
