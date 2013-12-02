#ifndef __SM2_HEADER_2011_01_28__
#define __SM2_HEADER_2011_01_28__

#include "miracl.h"
#include "sm3.h"


unsigned char *sm3_e(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *msg, int msg_len, unsigned char *e);
/*
功能：根据用户ID及公钥，求用于签名或验签的消息HASH值
[输入] userid： 用户ID
[输入] userid_len： userid的字节数
[输入] xa： 公钥的X坐标
[输入] xa_len: xa的字节数
[输入] ya： 公钥的Y坐标
[输入] ya_len: ya的字节数
[输入] msg：要签名的消息
[输入] msg_len： msg的字节数
[输出] e：32字节，用于签名或验签

返回值：
		NULL：       失败
		指向e的指针：成功
*/


int sm3_z(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *z);
/*
功能：根据用户ID及公钥，求Z值
[输入] userid： 用户ID
[输入] userid_len： userid的字节数
[输入] xa： 公钥的X坐标
[输入] xa_len: xa的字节数
[输入] ya： 公钥的Y坐标
[输入] ya_len: ya的字节数
[输出] z：32字节

返回值：
		－1：内存不足
		  0：成功
*/

int sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, int *wylen, unsigned char *privkey, int *privkeylen);
/*
功能：生成SM2公私钥对
[输出] wx：   公钥的X坐标，不足32字节在前面加0x00
[输出] wxlen: wx的字节数，32
[输出] wy：   公钥的Y坐标，不足32字节在前面加0x00
[输出] wylen: wy的字节数，32
[输出] privkey：私钥，不足32字节在前面加0x00
[输出] privkeylen： privkey的字节数，32
返回值：
0：失败
1：成功

*/

int sm2_sign(unsigned char *hash, int hashlen, unsigned char *privkey, int privkeylen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen);
/*
功能：SM2签名
[输入] hash：    sm3_e()的结果
[输入] hashlen： hash的字节数，应为32
[输入] privkey： 私钥
[输入] privkeylen： privkeylen的字节数

[输出] cr：  签名结果的第一部分，不足32字节在前面加0x00。
[输出] rlen：cr的字节数，32
[输出] cs：  签名结果的第二部分，不足32字节在前面加0x00。
[输出] slen：cs的字节数，32
返回值：
0：失败
1：成功
*/

int  sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen);
/*
功能：验证SM2签名
[输入] hash：    sm3_e()的结果
[输入] hashlen： hash的字节数，应为32
[输入] cr：  签名结果的第一部分
[输入] rlen：cr的字节数
[输入] cs：  签名结果的第二部分。
[输入] slen：cs的字节数
[输入] wx：   公钥的X坐标
[输入] wxlen: wx的字节数，不超过32字节
[输入] wy：   公钥的Y坐标
[输入] wylen: wy的字节数，不超过32字节

返回值：
		0：验证失败
		1：验证通过
*/

int  sm2_encrypt(unsigned char *msg, int msglen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen, unsigned char *outmsg);
/*
功能：用SM2公钥加密数据。加密结果比输入数据多96字节！
[输入] msg     要加密的数据
[输入] msglen：msg的字节数
[输入] wx：    公钥的X坐标
[输入] wxlen:  wx的字节数，不超过32字节
[输入] wy：    公钥的Y坐标
[输入] wylen:  wy的字节数，不超过32字节

[输出] outmsg: 加密结果，比输入数据多96字节！，C1（64字节）和C3（32字节）保留前导0x00

返回值：
		-1：        加密失败
		msglen+96： 加密成功
*/

int  sm2_decrypt(unsigned char *msg, int msglen, unsigned char *privkey, int privkeylen, unsigned char *outmsg);
/*
功能：用SM2私钥解密数据。解密结果比输入数据少96字节！
[输入] msg     要解密的数据，是sm2_encrypt()加密的结果，不少于96字节。
[输入] msglen：msg的字节数
[输入] privkey： 私钥
[输入] privkeylen： privkeylen的字节数

[输出] outmsg: 解密结果，比输入数据少96字节！

返回值：
		-1：        解密失败
		msglen-96： 解密成功
*/

int sm2_keyagreement_a(
    unsigned char *kxa, int kxalen,
    unsigned char *kya, int kyalen,
    unsigned char *xa, int xalen,
    unsigned char *ya, int yalen,
    unsigned char *private_a,   int private_a_len,
    unsigned char *xb, int xblen,
    unsigned char *yb, int yblen,
    unsigned char *ida, int idalen,
    unsigned char *idb, int idblen,
    unsigned char *kxb, int kxblen,
    unsigned char *kyb, int kyblen,
    unsigned char *private_a_tmp,  int private_a_tmp_len,
    unsigned int  keylen,
    unsigned char *keybuf,
    unsigned char *s1,
    unsigned char *sa
);
/*

功能：密钥协商的A方调用此函数协商出密钥keybuf。
说明：
[输入] (kxa, kya)是A方的临时公钥
[输入] (xa, ya)是A方的公钥
[输入] private_a是A方的私钥
[输入] (xb, yb)是B方的公钥
[输入] ida是A方的用户标识
[输入] idb是B方的用户标识
[输入] (kxb, kyb)是B方的临时公钥
[输入] private_a_tmp是A方的临时私钥
[输入] keylen是要约定的密钥字节数

[输出] keybuf是协商密钥输出缓冲区
[输出] s1是A产生的32字节的HASH值，应等于sb。如果为s1=NULL，则不输出。
[输出] sa是A方产生的32字节的HASH值，要传送给B，用于验证协商的正确性。如果为sa=NULL，则不输出。


返回值：0－失败  1－成功

*/


int sm2_keyagreement_b(
    unsigned char *kxb, int kxblen,
    unsigned char *kyb, int kyblen,
    unsigned char *xb, int xblen,
    unsigned char *yb, int yblen,
    unsigned char *private_b,   int private_b_len,
    unsigned char *xa, int xalen,
    unsigned char *ya, int yalen,
    unsigned char *idb, int idblen,
    unsigned char *ida, int idalen,
    unsigned char *kxa, int kxalen,
    unsigned char *kya, int kyalen,
    unsigned char *private_b_tmp,  int private_b_tmp_len,
    unsigned int  keylen,
    unsigned char *keybuf,
    unsigned char *s2,
    unsigned char *sb
);

/*

功能：密钥协商的B方调用此函数协商出密钥keybuf。
说明：
[输入] (kxb, kyb)是B方的临时公钥
[输入] (xb, yb)是B方的公钥
[输入] private_b是B方的私钥
[输入] (xa, ya)是A方的公钥
[输入] idb是B方的用户标识
[输入] ida是A方的用户标识
[输入] (kxa, kya)是A方的临时公钥
[输入] private_b_tmp是B方的临时私钥
[输入] keylen是要约定的密钥字节数

[输出] keybuf是协商密钥输出缓冲区
[输出] s2是B产生的32字节的HASH值，应等于sa。如果为s2=NULL，则不输出。
[输出] sb是B方产生的32字节的HASH值，要传送给A，用于验证协商的正确性。如果为sb=NULL，则不输出。


返回值：0－失败  1－成功

*/

#endif
