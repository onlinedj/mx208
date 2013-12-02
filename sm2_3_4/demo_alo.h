#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "miracl.h"
#include "sm2.h"
#include "sm4.h"
//#include "mxpci_spi.h"


#define ECCref_MAX_BITS     256 
#define ECCref_MAX_LEN      ((ECCref_MAX_BITS+7) / 8)
typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN]; 
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*
功能：生成SM2公私钥对
[输出] pubkey : 输出公钥
[输出] privkey: 输出私钥
*/
int alo_getKeypair(ECCrefPublicKey pubkey,ECCrefPrivateKey privkey);

/*
功能：用SM2公钥加密数据。加密结果比输入数据多96字节！
[输入] msg     要加密的数据
[输入] msglen：msg的字节数
[输入] pubkey 输入公钥

[输出] outmsg: 加密结果，比输入数据多96字节

返回值：
		-1：        加密失败
		msglen+96： 加密成功
*/
int alo_ECCencrpyt(unsigned char *msg, int msglen, ECCrefPublicKey pubkey ,unsigned char *outmsg);

/*
功能：用SM2私钥解密数据。解密结果比输入数据少96字节！
[输入] msg     要解密的数据，不少于96字节。
[输入] msglen：msg的字节数
[输入] privkey： 私钥
[输入] privkeylen： privkeylen的字节数

[输出] outmsg: 解密结果，比输入数据少96字节！

返回值：
		-1：        解密失败
		msglen-96： 解密成功
*/
int alo_ECCdecrypt(unsigned char *msg, int msglen, ECCrefPrivateKey privkey, unsigned char *outmsg);

/*
in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
out:       输出的结果，是SM4_BLOCK_SIZE的整倍数
length:    in的字节数
key:       16 字节的用户密钥
enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
*/
void alo_ECBencrpyt(const U8 *in, U8 *out,const U32 length, const U8 *key,const U32 enc);