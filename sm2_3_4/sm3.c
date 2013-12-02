/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM3 Hash Cipher Algorithm: Digest length is 256-bit
 * ============================================================================
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "sm3.h"


#define nl2c(l,c)	(*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 8)  & 0xff), \
					 *((c)++) = (unsigned char)(((l)    )   & 0xff))

#define c_2_nl(c)	((*(c) << 24) | (*(c+1) << 16) | (*(c+2) << 8) | *(c+3))
#define ROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C))))

#define TH 0x79cc4519
#define TL 0x7a879d8a
#define FFH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FFL(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GGL(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))
#define P0(X)  ((X) ^ (((X) << 9) | ((X) >> 23)) ^ (((X) << 17) | ((X) >> 15)))
#define P1(X)  ((X) ^ (((X) << 15) | ((X) >> 17)) ^ (((X) << 23) | ((X) >> 9)))

#define DEBUG_SM3 0

#if DEBUG_SM3
void PrintBuf(unsigned char *buf, int	buflen) 
{
	int i;
	printf("\n");
	printf("len = %d\n", buflen);
	for(i=0; i<buflen; i++) {
  	if (i % 32 != 31)
  	  printf("%02x", buf[i]);
  	  else
  	  printf("%02x\n", buf[i]);
  }
  printf("\n");
  return;
}
#endif

void sm3_block(SM3_CTX *ctx)
{
	register int j, k;
	register unsigned int t;
	register unsigned int ss1, ss2, tt1, tt2;
	register unsigned int a, b, c, d, e, f, g, h;
	unsigned int w[132];


	for(j = 0; j < 16; j++)
		w[j] = ctx->data[j];

	for(j = 16; j < 68; j++)
	{
		t = w[j-16] ^ w[j-9] ^ ROTATE(w[j-3], 15);
		w[j] = P1(t) ^ ROTATE(w[j-13], 7) ^ w[j-6];
	}


	for(j = 0, k = 68; j < 64; j++, k++)
	{
		w[k] = w[j] ^ w[j+4];
	}


	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	for(j = 0; j < 16; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TH, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFH(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGH(e, f, g) + h + ss1 + w[j];

		d = c; 
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	for(j = 16; j < 33; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	for(j = 33; j < 64; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, (j-32)), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}


	ctx->h[0]  ^=  a ;
	ctx->h[1]  ^=  b ;
	ctx->h[2]  ^=  c ;
	ctx->h[3]  ^=  d ;
	ctx->h[4]  ^=  e ;
	ctx->h[5]  ^=  f ;
	ctx->h[6]  ^=  g ;
	ctx->h[7]  ^=  h ;

}


void SM3_Init (SM3_CTX *ctx)
{
	ctx->h[0] = 0x7380166fUL;
	ctx->h[1] = 0x4914b2b9UL;
	ctx->h[2] = 0x172442d7UL;
	ctx->h[3] = 0xda8a0600UL;
	ctx->h[4] = 0xa96f30bcUL;
	ctx->h[5] = 0x163138aaUL;
	ctx->h[6] = 0xe38dee4dUL;
	ctx->h[7] = 0xb0fb0e4eUL;
	ctx->Nl   = 0;
	ctx->Nh   = 0;
	ctx->num  = 0;
}

void SM3_Update(SM3_CTX *ctx, const void *data, int len)
{
	unsigned char *d;
	unsigned int l;
	int i, sw, sc;


	if (len == 0)
		return;

	l = (ctx->Nl + (len << 3)) & 0xffffffffL;
	if (l < ctx->Nl) /* overflow */
		ctx->Nh++;
	ctx->Nh += (len >> 29);
	ctx->Nl = l;


	d = (unsigned char *)data;

	while (len >= SM3_CBLOCK)
	{
		ctx->data[0] = c_2_nl(d);
		d += 4;
		ctx->data[1] = c_2_nl(d);
		d += 4;
		ctx->data[2] = c_2_nl(d);
		d += 4;
		ctx->data[3] = c_2_nl(d);
		d += 4;
		ctx->data[4] = c_2_nl(d);
		d += 4;
		ctx->data[5] = c_2_nl(d);
		d += 4;
		ctx->data[6] = c_2_nl(d);
		d += 4;
		ctx->data[7] = c_2_nl(d);
		d += 4;
		ctx->data[8] = c_2_nl(d);
		d += 4;
		ctx->data[9] = c_2_nl(d);
		d += 4;
		ctx->data[10] = c_2_nl(d);
		d += 4;
		ctx->data[11] = c_2_nl(d);
		d += 4;
		ctx->data[12] = c_2_nl(d);
		d += 4;
		ctx->data[13] = c_2_nl(d);
		d += 4;
		ctx->data[14] = c_2_nl(d);
		d += 4;
		ctx->data[15] = c_2_nl(d);
		d += 4;

		sm3_block(ctx);
		len -= SM3_CBLOCK;
	}

	if(len > 0)
	{
		memset(ctx->data, 0, 64);
		ctx->num = len + 1;
		sw = len >> 2;
		sc = len & 0x3;

		for(i = 0; i < sw; i++)
		{
			ctx->data[i] = c_2_nl(d);
			d += 4;
		}

		switch(sc)
		{
			case 0:
				ctx->data[i] = 0x80000000;
				break;
			case 1:
				ctx->data[i] = (d[0] << 24) | 0x800000;
				break;
			case 2:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | 0x8000;
				break;
			case 3:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | 0x80;
				break;
		}

	}


}

void SM3_Final(unsigned char *md, SM3_CTX *ctx)
{

	if(ctx->num == 0)
	{
		memset(ctx->data, 0, 64);
		ctx->data[0] = 0x80000000;
		ctx->data[14] = ctx->Nh;
		ctx->data[15] = ctx->Nl;
	}
	else
	{
		if(ctx->num <= SM3_LAST_BLOCK)
		{
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
		else
		{
			sm3_block(ctx);
			memset(ctx->data, 0, 56);
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
	}

	sm3_block(ctx);

	nl2c(ctx->h[0], md);
	nl2c(ctx->h[1], md);
	nl2c(ctx->h[2], md);
	nl2c(ctx->h[3], md);
	nl2c(ctx->h[4], md);
	nl2c(ctx->h[5], md);
	nl2c(ctx->h[6], md);
	nl2c(ctx->h[7], md);
}

unsigned char *sm3(const unsigned char *data, int datalen, unsigned char *digest)
{
/*
功能：    用SM3算法做摘要

参数说明：
		data     [输入] 用于做摘要的数据
		datalen  [输入] data的字节数
		digest   [输出] 32字节的摘要值

返回值：指向digest的指针

*/	
	
	SM3_CTX ctx;

	SM3_Init(&ctx);
	SM3_Update(&ctx, data, datalen);
	SM3_Final(digest, &ctx);
	memset(&ctx, 0, sizeof(ctx));

	return(digest);
}


unsigned char *sm3_hmac(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac)
{
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
	
/*
散列消息鉴别码，简称HMAC，是一种基于消息鉴别码MAC（Message Authentication Code）的鉴别机制。
使用HMAC时，消息通讯的双方，通过验证消息中加入的鉴别密钥K来鉴别消息的真伪；
HMAC还引入了一个散列函数H，对消息进行加密，进一步确保消息鉴别的安全性和有效性。

HMAC如下定义：
	H: 加密用散列函数（此处为SM3）;
	K: 密钥（此处密钥为32字节种子密钥）
	B：数据块的字长（SM3算法的数据块的长度为64BYTE）
	L: 散列函数输出的数据字节长度（SM3中L=32）
	Text: 输入的消息（此处为当前时间除以步长得到的结果，或者是当前时间除以步长串联挑战信息）

	密钥K的长度可以是小于等于数据块字长的正整数值，K的长度若是比B大，首先用使用散列函数H作用于它，
	然后用H输出的L长度字符串作为在HMAC中实际使用的密钥。一般情况下，推荐的最小密钥K长度是L个字长。（与H的输出数据长度相等）。

	定义两个固定且不同的字符串ipad,opad（'i','o'标志内部与外部）
		ipad =值为0x36的B个bytes
		opad =值为0x5C的B个bytes.

计算'text'的HMAC：

        HMAC(K,Text)=H( K XOR opad, H(K XOR ipad, Text))	 	（式-2）

详细的算法过程如下：
(1) 在密钥K后面添加0来创建一个字长为B的字符串。(例如，如果K的字长是32字节，B＝64字节，则K后会加入32个零字节0x00)
(2)	将上一步生成的B字长的字符串与ipad做异或运算。
(3)	将数据流text填充至第二步的结果字符串中。

(4)	用H作用于第三步生成的数据流。
(5)	将第一步生成的B字长字符串与opad做异或运算。
(6)	再将第四步的结果填充进第五步的结果中。
(7)	用H作用于第六步生成的数据流，输出最终结果

*/

	unsigned char keypaded[64];
	unsigned char *p;
	int i;

//#1
	memset(keypaded, 0, sizeof(keypaded));
	if(keylen > 64)
	{
		sm3(key, keylen, keypaded);
	}
	else
	{
		memcpy(keypaded, key, keylen);
	}

//#2

	p = malloc(64 + textlen + 32);
	if( NULL == p)
		return NULL;

	for(i = 0; i < 64; i++)
		p[i] = keypaded[i] ^ 0x36;
//#3

	memcpy(p + 64, text, textlen);

//#4
	sm3(p, 64 + textlen, hmac);

//#5
	for(i = 0; i < 64; i++)
		p[i] = keypaded[i] ^ 0x5C;

//#6
	memcpy(p + 64, hmac, 32);

//#7
	sm3(p, 64 + 32, hmac);


	free(p);

	return hmac;

}


#if DEBUG_SM3

int main()
{
	unsigned char data[] = "abc";
	/*66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0*/
	unsigned char data1[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	/*debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732*/
	unsigned char md[SM3_DIGEST_LENGTH];

	clock_t start,end;
	double tt;
	int j;


	unsigned char key[]="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	sm3_hmac(key, 65, data, strlen(data), md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	memset(md, 0, sizeof(md));
	sm3(data, 3, md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	memset(md, 0, sizeof(md));
	sm3(data1, 64, md);
#if DEBUG_SM3
	PrintBuf(md, 32);
#endif

	start = clock();

	for(j=0;j<1000000;j++)
	{
		sm3(data1, 55, md);
	}


	end = clock();

	tt = (double)(end-start)/CLOCKS_PER_SEC;
	printf("speed:%lfMbps\n", (double)512/tt);

	return 0;
}
#endif

