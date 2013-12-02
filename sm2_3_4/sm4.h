/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM4 Block Cipher Algorithm: Block length and key length are both 128-bit
 * ============================================================================
 */

#ifndef _SM4_HEADER_H_
#define _SM4_HEADER_H_   1

#ifndef U8
#define U8 unsigned char
#endif

#ifndef U32
#define U32 unsigned int
#endif

#define SM4_ENCRYPT    1
#define SM4_DECRYPT    0

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16


void sm4_set_key(const U8 *userkey, U32 *round_key);
/*
userkey:   16 字节的用户密钥
round_key: 32 长字的层密钥，待设置
*/


void sm4_encrypt(const U8 *in, U8 *out, const U32 *round_key);
/*
in:        16 字节的明文
out:       16 字节的密文
round_key: 32 长字的层密钥，已设置
*/


void sm4_decrypt(const U8 *in, U8 *out, const U32 *round_key);
/*
in:        16 字节的密文
out:       16 字节的明文
round_key: 32 长字的层密钥，已设置
*/


void sm4_ecb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U32 enc);
/*
in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
out:       输出的结果，是SM4_BLOCK_SIZE的整倍数
length:    in的字节数
key:       16 字节的用户密钥
enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
*/


void sm4_cbc_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc);
/*
in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
out:       输出的结果，是SM4_BLOCK_SIZE的整倍数
length:    in的字节数
key:       16 字节的用户密钥
ivec:      16 字节的初始化向量
enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
*/

void sm4_cbc_mac(const U8 *in, U8 *out,
                 const U32 length, const U8 *key,
                 const U8 *ivec);
/*
in:        用来计算MAC的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
out:       输出的MAC，16字节
length:    in的字节数
key:       16 字节的用户密钥
ivec:      16 字节的初始化向量
*/


void sm4_cfb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc) ;

/*
in:        要加密或解密的数据。
out:       输出的结果
length:    in的字节数
key:       16 字节的用户密钥
ivec:      16 字节的初始化向量
enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
*/

void sm4_ofb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec) ;
/*
in:        要加密或解密的数据。
out:       输出的结果
length:    in的字节数
key:       16 字节的用户密钥
ivec:      16 字节的初始化向量
*/


#endif /* _SM4_HEADER_H_ */
