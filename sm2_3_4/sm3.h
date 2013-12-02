/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM3 Hash Cipher Algorithm: Digest length is 256-bit
 * ============================================================================
 */

#ifndef __SM3_HEADER__
#define __SM3_HEADER__

unsigned char *sm3(const unsigned char *data, int datalen, unsigned char *digest);
/*
功能：    用SM3算法做摘要

参数说明：
		data     [输入] 用于做摘要的数据
		datalen  [输入] data的字节数
		digest   [输出] 32字节的摘要值

返回值：指向digest的指针

*/


unsigned char *sm3_hmac(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac);
/*
功能：    用SM3算法做HMAC

参数说明：
		key      [输入] 用于做HMAC的密钥
		keylen   [输入] key的字节数
		text     [输入] 用于做HMAC的数据
		textlen  [输入] text的字节数
		hmac     [输出] 32字节的HMAC值

返回值：指向hmac的指针

*/


#define  SM3_LBLOCK         16
#define  SM3_CBLOCK         64
#define  SM3_DIGEST_LENGTH  32
#define  SM3_LAST_BLOCK     56

typedef struct SM3state_st
{
	unsigned int h[8];
	unsigned int Nl,Nh;
	unsigned int data[SM3_LBLOCK];
	unsigned int  num;
} SM3_CTX;

void SM3_Init (SM3_CTX *ctx);

void SM3_Update(SM3_CTX *ctx, const void *data, int len);
/*
注意：除了最后一包外，len必须是64字节的整倍数。
*/

void SM3_Final(unsigned char *md, SM3_CTX *ctx);


#endif
