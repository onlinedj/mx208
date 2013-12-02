/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM4 Block Cipher Algorithm: Block length and key length are both 128-bit
 * ============================================================================
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "sm4.h"


#define MAKE_DWORD(a,b,c,d) (((a) << 24 ) | ((b) << 16) | ((c) << 8) | (d))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define NONLINEAR_CHANGE(a)  ((SBOX[(a) >> 24] << 24) \
                         | (SBOX[((a) >> 16) & 0xFF] << 16 ) \
                         | (SBOX[((a) >> 8)  & 0xFF] << 8  ) \
                         | (SBOX[ (a) & 0xFF]))

#define LINE_CHANGE_L(a) (a ^ ROTATE_LEFT(a,2) ^ ROTATE_LEFT(a,10) ^ ROTATE_LEFT(a,18) ^ ROTATE_LEFT(a,24))
#define LINE_CHANGE_L1(a) (a ^ ROTATE_LEFT(a,13) ^ ROTATE_LEFT(a,23))
#define T(x0, x1, x2, x3, rk) (x0^LINE_CHANGE_L(NONLINEAR_CHANGE(x1^x2^x3^rk)))

const U32 SBOX[256] =
{
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

const U32 FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
const U32 CK[32] =
{
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

void sm4_set_key(const U8 *userkey, U32 *round_key)
{
    /*
    userkey:   16 字节的用户密钥
    round_key: 32 长字的层密钥，待设置
    */
    /*	register int i;
    	U32 k[36];
    */
    U32 k[4];

    k[0] = MAKE_DWORD (userkey[0],  userkey[1],  userkey[2],  userkey[3])  ^ FK[0];
    k[1] = MAKE_DWORD (userkey[4],  userkey[5],  userkey[6],  userkey[7])  ^ FK[1];
    k[2] = MAKE_DWORD (userkey[8],  userkey[9],  userkey[10], userkey[11]) ^ FK[2];
    k[3] = MAKE_DWORD (userkey[12], userkey[13], userkey[14], userkey[15]) ^ FK[3];

#if 0
    for(i = 0; i < 32; i++)
    {
        k[i + 4] = k[i] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
        round_key[i] = k[i + 4];
    }
#else
    round_key[ 0] =         k[ 0] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE(         k[ 1] ^         k[ 2] ^         k[ 3] ^ CK[ 0]));
    round_key[ 1] =         k[ 1] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE(         k[ 2] ^         k[ 3] ^ round_key[ 0] ^ CK[ 1]));
    round_key[ 2] =         k[ 2] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE(         k[ 3] ^ round_key[ 0] ^ round_key[ 1] ^ CK[ 2]));
    round_key[ 3] =         k[ 3] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 0] ^ round_key[ 1] ^ round_key[ 2] ^ CK[ 3]));
    round_key[ 4] = round_key[ 0] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 1] ^ round_key[ 2] ^ round_key[ 3] ^ CK[ 4]));
    round_key[ 5] = round_key[ 1] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 2] ^ round_key[ 3] ^ round_key[ 4] ^ CK[ 5]));
    round_key[ 6] = round_key[ 2] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 3] ^ round_key[ 4] ^ round_key[ 5] ^ CK[ 6]));
    round_key[ 7] = round_key[ 3] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 4] ^ round_key[ 5] ^ round_key[ 6] ^ CK[ 7]));
    round_key[ 8] = round_key[ 4] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 5] ^ round_key[ 6] ^ round_key[ 7] ^ CK[ 8]));
    round_key[ 9] = round_key[ 5] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 6] ^ round_key[ 7] ^ round_key[ 8] ^ CK[ 9]));
    round_key[10] = round_key[ 6] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 7] ^ round_key[ 8] ^ round_key[ 9] ^ CK[10]));
    round_key[11] = round_key[ 7] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 8] ^ round_key[ 9] ^ round_key[10] ^ CK[11]));
    round_key[12] = round_key[ 8] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[ 9] ^ round_key[10] ^ round_key[11] ^ CK[12]));
    round_key[13] = round_key[ 9] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[10] ^ round_key[11] ^ round_key[12] ^ CK[13]));
    round_key[14] = round_key[10] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[11] ^ round_key[12] ^ round_key[13] ^ CK[14]));
    round_key[15] = round_key[11] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[12] ^ round_key[13] ^ round_key[14] ^ CK[15]));
    round_key[16] = round_key[12] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[13] ^ round_key[14] ^ round_key[15] ^ CK[16]));
    round_key[17] = round_key[13] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[14] ^ round_key[15] ^ round_key[16] ^ CK[17]));
    round_key[18] = round_key[14] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[15] ^ round_key[16] ^ round_key[17] ^ CK[18]));
    round_key[19] = round_key[15] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[16] ^ round_key[17] ^ round_key[18] ^ CK[19]));
    round_key[20] = round_key[16] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[17] ^ round_key[18] ^ round_key[19] ^ CK[20]));
    round_key[21] = round_key[17] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[18] ^ round_key[19] ^ round_key[20] ^ CK[21]));
    round_key[22] = round_key[18] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[19] ^ round_key[20] ^ round_key[21] ^ CK[22]));
    round_key[23] = round_key[19] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[20] ^ round_key[21] ^ round_key[22] ^ CK[23]));
    round_key[24] = round_key[20] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[21] ^ round_key[22] ^ round_key[23] ^ CK[24]));
    round_key[25] = round_key[21] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[22] ^ round_key[23] ^ round_key[24] ^ CK[25]));
    round_key[26] = round_key[22] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[23] ^ round_key[24] ^ round_key[25] ^ CK[26]));
    round_key[27] = round_key[23] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[24] ^ round_key[25] ^ round_key[26] ^ CK[27]));
    round_key[28] = round_key[24] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[25] ^ round_key[26] ^ round_key[27] ^ CK[28]));
    round_key[29] = round_key[25] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[26] ^ round_key[27] ^ round_key[28] ^ CK[29]));
    round_key[30] = round_key[26] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[27] ^ round_key[28] ^ round_key[29] ^ CK[30]));
    round_key[31] = round_key[27] ^ LINE_CHANGE_L1( NONLINEAR_CHANGE( round_key[28] ^ round_key[29] ^ round_key[30] ^ CK[31]));

#endif

}


void sm4_encrypt(const U8 *in, U8 *out, const U32 *round_key)
{
    /*
    in:        16 字节的明文
    out:       16 字节的密文
    round_key: 32 长字的层密钥，已设置
    */
    //	register int i;
    U32 x[36];

    x[0] = MAKE_DWORD (in[0],  in[1],  in[2],  in[3]);
    x[1] = MAKE_DWORD (in[4],  in[5],  in[6],  in[7]);
    x[2] = MAKE_DWORD (in[8],  in[9],  in[10], in[11]);
    x[3] = MAKE_DWORD (in[12], in[13], in[14], in[15]);

#if 0
    for(i = 0; i < 32; i++)
    {
        x[i + 4] = T(x[i], x[i + 1], x[i + 2], x[i + 3], round_key[i]);
    }
#else
    x[ 4] = T(x[ 0], x[ 1], x[ 2], x[ 3], round_key[ 0]);
    x[ 5] = T(x[ 1], x[ 2], x[ 3], x[ 4], round_key[ 1]);
    x[ 6] = T(x[ 2], x[ 3], x[ 4], x[ 5], round_key[ 2]);
    x[ 7] = T(x[ 3], x[ 4], x[ 5], x[ 6], round_key[ 3]);
    x[ 8] = T(x[ 4], x[ 5], x[ 6], x[ 7], round_key[ 4]);
    x[ 9] = T(x[ 5], x[ 6], x[ 7], x[ 8], round_key[ 5]);
    x[10] = T(x[ 6], x[ 7], x[ 8], x[ 9], round_key[ 6]);
    x[11] = T(x[ 7], x[ 8], x[ 9], x[10], round_key[ 7]);
    x[12] = T(x[ 8], x[ 9], x[10], x[11], round_key[ 8]);
    x[13] = T(x[ 9], x[10], x[11], x[12], round_key[ 9]);
    x[14] = T(x[10], x[11], x[12], x[13], round_key[10]);
    x[15] = T(x[11], x[12], x[13], x[14], round_key[11]);
    x[16] = T(x[12], x[13], x[14], x[15], round_key[12]);
    x[17] = T(x[13], x[14], x[15], x[16], round_key[13]);
    x[18] = T(x[14], x[15], x[16], x[17], round_key[14]);
    x[19] = T(x[15], x[16], x[17], x[18], round_key[15]);
    x[20] = T(x[16], x[17], x[18], x[19], round_key[16]);
    x[21] = T(x[17], x[18], x[19], x[20], round_key[17]);
    x[22] = T(x[18], x[19], x[20], x[21], round_key[18]);
    x[23] = T(x[19], x[20], x[21], x[22], round_key[19]);
    x[24] = T(x[20], x[21], x[22], x[23], round_key[20]);
    x[25] = T(x[21], x[22], x[23], x[24], round_key[21]);
    x[26] = T(x[22], x[23], x[24], x[25], round_key[22]);
    x[27] = T(x[23], x[24], x[25], x[26], round_key[23]);
    x[28] = T(x[24], x[25], x[26], x[27], round_key[24]);
    x[29] = T(x[25], x[26], x[27], x[28], round_key[25]);
    x[30] = T(x[26], x[27], x[28], x[29], round_key[26]);
    x[31] = T(x[27], x[28], x[29], x[30], round_key[27]);
    x[32] = T(x[28], x[29], x[30], x[31], round_key[28]);
    x[33] = T(x[29], x[30], x[31], x[32], round_key[29]);
    x[34] = T(x[30], x[31], x[32], x[33], round_key[30]);
    x[35] = T(x[31], x[32], x[33], x[34], round_key[31]);
#endif


    out[0] = (U8 )( x[35] >> 24);
    out[1] = (U8 )( x[35] >> 16);
    out[2] = (U8 )( x[35] >> 8 );
    out[3] = (U8 )( x[35] );

    out[4] = (U8 )( x[34] >> 24);
    out[5] = (U8 )( x[34] >> 16);
    out[6] = (U8 )( x[34] >> 8 );
    out[7] = (U8 )( x[34] );

    out[8] = (U8 )( x[33] >> 24);
    out[9] = (U8 )( x[33] >> 16);
    out[10] = (U8 )( x[33] >> 8 );
    out[11] = (U8 )( x[33] );

    out[12] = (U8 )( x[32] >> 24);
    out[13] = (U8 )( x[32] >> 16);
    out[14] = (U8 )( x[32] >> 8 );
    out[15] = (U8 )( x[32] );

}

void sm4_decrypt(const U8 *in, U8 *out, const U32 *round_key)
{
    /*
    in:        16 字节的密文
    out:       16 字节的明文
    round_key: 32 长字的层密钥，已设置
    */
    //	register int i;
    U32 x[36];

    x[0] = MAKE_DWORD (in[0],  in[1],  in[2],  in[3]);
    x[1] = MAKE_DWORD (in[4],  in[5],  in[6],  in[7]);
    x[2] = MAKE_DWORD (in[8],  in[9],  in[10], in[11]);
    x[3] = MAKE_DWORD (in[12], in[13], in[14], in[15]);

#if 0
    for(i = 0; i < 32; i++)
    {
        x[i + 4] = T(x[i], x[i + 1], x[i + 2], x[i + 3], round_key[31 - i]);
    }
#else
    x[ 4] = T(x[ 0], x[ 1], x[ 2], x[ 3], round_key[31]);
    x[ 5] = T(x[ 1], x[ 2], x[ 3], x[ 4], round_key[30]);
    x[ 6] = T(x[ 2], x[ 3], x[ 4], x[ 5], round_key[29]);
    x[ 7] = T(x[ 3], x[ 4], x[ 5], x[ 6], round_key[28]);
    x[ 8] = T(x[ 4], x[ 5], x[ 6], x[ 7], round_key[27]);
    x[ 9] = T(x[ 5], x[ 6], x[ 7], x[ 8], round_key[26]);
    x[10] = T(x[ 6], x[ 7], x[ 8], x[ 9], round_key[25]);
    x[11] = T(x[ 7], x[ 8], x[ 9], x[10], round_key[24]);
    x[12] = T(x[ 8], x[ 9], x[10], x[11], round_key[23]);
    x[13] = T(x[ 9], x[10], x[11], x[12], round_key[22]);
    x[14] = T(x[10], x[11], x[12], x[13], round_key[21]);
    x[15] = T(x[11], x[12], x[13], x[14], round_key[20]);
    x[16] = T(x[12], x[13], x[14], x[15], round_key[19]);
    x[17] = T(x[13], x[14], x[15], x[16], round_key[18]);
    x[18] = T(x[14], x[15], x[16], x[17], round_key[17]);
    x[19] = T(x[15], x[16], x[17], x[18], round_key[16]);
    x[20] = T(x[16], x[17], x[18], x[19], round_key[15]);
    x[21] = T(x[17], x[18], x[19], x[20], round_key[14]);
    x[22] = T(x[18], x[19], x[20], x[21], round_key[13]);
    x[23] = T(x[19], x[20], x[21], x[22], round_key[12]);
    x[24] = T(x[20], x[21], x[22], x[23], round_key[11]);
    x[25] = T(x[21], x[22], x[23], x[24], round_key[10]);
    x[26] = T(x[22], x[23], x[24], x[25], round_key[ 9]);
    x[27] = T(x[23], x[24], x[25], x[26], round_key[ 8]);
    x[28] = T(x[24], x[25], x[26], x[27], round_key[ 7]);
    x[29] = T(x[25], x[26], x[27], x[28], round_key[ 6]);
    x[30] = T(x[26], x[27], x[28], x[29], round_key[ 5]);
    x[31] = T(x[27], x[28], x[29], x[30], round_key[ 4]);
    x[32] = T(x[28], x[29], x[30], x[31], round_key[ 3]);
    x[33] = T(x[29], x[30], x[31], x[32], round_key[ 2]);
    x[34] = T(x[30], x[31], x[32], x[33], round_key[ 1]);
    x[35] = T(x[31], x[32], x[33], x[34], round_key[ 0]);
#endif

    out[0] = (U8 )( x[35] >> 24);
    out[1] = (U8 )( x[35] >> 16);
    out[2] = (U8 )( x[35] >> 8 );
    out[3] = (U8 )( x[35] );

    out[4] = (U8 )( x[34] >> 24);
    out[5] = (U8 )( x[34] >> 16);
    out[6] = (U8 )( x[34] >> 8 );
    out[7] = (U8 )( x[34] );

    out[8] = (U8 )( x[33] >> 24);
    out[9] = (U8 )( x[33] >> 16);
    out[10] = (U8 )( x[33] >> 8 );
    out[11] = (U8 )( x[33] );

    out[12] = (U8 )( x[32] >> 24);
    out[13] = (U8 )( x[32] >> 16);
    out[14] = (U8 )( x[32] >> 8 );
    out[15] = (U8 )( x[32] );


}


void sm4_ecb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U32 enc)
{
    /*
    in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
    out:       输出的结果，是SM4_BLOCK_SIZE的整倍数
    length:    in的字节数
    key:       16 字节的用户密钥
    enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
    */
    U32 n;
    U32 len = length;
    U32 round_key[32];


    if((in == NULL) || (out == NULL) || (key == NULL))
        return;

    if((SM4_ENCRYPT != enc) && (SM4_DECRYPT != enc))
        return;

    sm4_set_key(key, round_key);

    while (len >= SM4_BLOCK_SIZE)
    {
        for(n = 0; n < SM4_BLOCK_SIZE; ++n)
            out[n] = in[n];
        if (SM4_ENCRYPT == enc)
            sm4_encrypt(out, out, round_key);
        else
            sm4_decrypt(out, out, round_key);

        len -= SM4_BLOCK_SIZE;
        in += SM4_BLOCK_SIZE;
        out += SM4_BLOCK_SIZE;
    }

    if (len)
    {
        for(n = 0; n < len; ++n)
            out[n] = in[n];
        for(n = len; n < SM4_BLOCK_SIZE; ++n)
            out[n] = 0;
        if (SM4_ENCRYPT == enc)
            sm4_encrypt(out, out, round_key);
        else
            sm4_decrypt(out, out, round_key);
    }

}



void sm4_cbc_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc)
{
    /*
    in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
    out:       输出的结果，是SM4_BLOCK_SIZE的整倍数
    length:    in的字节数
    key:       16 字节的用户密钥
    ivec:      16 字节的初始化向量
    enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
    */
    U32 n;
    U32 len = length;
    U8 tmp[SM4_BLOCK_SIZE];
    const U8 *iv = ivec;
    U32 round_key[32];
    U8 iv_tmp[SM4_BLOCK_SIZE];


    if((in == NULL) || (out == NULL) || (key == NULL) || (ivec == NULL))
        return;

    if((SM4_ENCRYPT != enc) && (SM4_DECRYPT != enc))
        return;

    sm4_set_key(key, round_key);

    if (SM4_ENCRYPT == enc)
    {
        while (len >= SM4_BLOCK_SIZE)
        {
            for(n = 0; n < SM4_BLOCK_SIZE; ++n)
                out[n] = in[n] ^ iv[n];
            sm4_encrypt(out, out, round_key);
            iv = out;
            len -= SM4_BLOCK_SIZE;
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
        }

        if (len)
        {
            for(n = 0; n < len; ++n)
                out[n] = in[n] ^ iv[n];
            for(n = len; n < SM4_BLOCK_SIZE; ++n)
                out[n] = iv[n];
            sm4_encrypt(out, out, round_key);
            iv = out;
        }
    }
    else if (in != out)
    {
        while (len >= SM4_BLOCK_SIZE)
        {
            sm4_decrypt(in, out, round_key);
            for(n = 0; n < SM4_BLOCK_SIZE; ++n)
                out[n] ^= iv[n];
            iv = in;
            len -= SM4_BLOCK_SIZE;
            in  += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
        }
        if (len)
        {
            sm4_decrypt(in, tmp, round_key);
            for(n = 0; n < len; ++n)
                out[n] = tmp[n] ^ iv[n];
            iv = in;
        }
    }
    else
    {
        memcpy(iv_tmp, ivec, SM4_BLOCK_SIZE);
        while (len >= SM4_BLOCK_SIZE)
        {
            memcpy(tmp, in, SM4_BLOCK_SIZE);
            sm4_decrypt(in, out, round_key);
            for(n = 0; n < SM4_BLOCK_SIZE; ++n)
                out[n] ^= iv_tmp[n];
            memcpy(iv_tmp, tmp, SM4_BLOCK_SIZE);
            len -= SM4_BLOCK_SIZE;
            in += SM4_BLOCK_SIZE;
            out += SM4_BLOCK_SIZE;
        }
        if (len)
        {
            memcpy(tmp, in, SM4_BLOCK_SIZE);
            sm4_decrypt(tmp, out, round_key);
            for(n = 0; n < len; ++n)
                out[n] ^= iv_tmp[n];
            for(n = len; n < SM4_BLOCK_SIZE; ++n)
                out[n] = tmp[n];
        }
    }
}


void sm4_cbc_mac(const U8 *in, U8 *out,
                 const U32 length, const U8 *key,
                 const U8 *ivec)
{
    /*
    in:        要加密或解密的数据，如果不是SM4_BLOCK_SIZE的整倍数，函数自动以0x00补齐。
    out:       输出的MAC，16字节
    length:    in的字节数
    key:       16 字节的用户密钥
    ivec:      16 字节的初始化向量
    */
    U32 n;
    U32 len = length;
    const U8 *iv = ivec;
    U32 round_key[32];


    if((in == NULL) || (out == NULL) || (key == NULL) || (ivec == NULL))
        return;


    sm4_set_key(key, round_key);

    while (len >= SM4_BLOCK_SIZE)
    {
        for(n = 0; n < SM4_BLOCK_SIZE; ++n)
            out[n] = in[n] ^ iv[n];
        sm4_encrypt(out, out, round_key);
        iv = out;
        len -= SM4_BLOCK_SIZE;
        in += SM4_BLOCK_SIZE;
    }

    if (len)
    {
        for(n = 0; n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for(n = len; n < SM4_BLOCK_SIZE; ++n)
            out[n] = iv[n];
        sm4_encrypt(out, out, round_key);
    }

}



void sm4_cfb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc)
{
    /*
    in:        要加密或解密的数据。
    out:       输出的结果
    length:    in的字节数
    key:       16 字节的用户密钥
    ivec:      16 字节的初始化向量
    enc:       加密或解密，SM4_ENCRYPT/SM4_DECRYPT
    */
    U32 n = 0;
    U32 l = length;
    U8 c;
    U32 round_key[32];
    U8 iv[SM4_BLOCK_SIZE];

    if((in == NULL) || (out == NULL) || (key == NULL) || (ivec == NULL))
        return;

    if((SM4_ENCRYPT != enc) && (SM4_DECRYPT != enc))
        return;

    sm4_set_key(key, round_key);
    memcpy(iv, ivec, SM4_BLOCK_SIZE);

    if (enc == SM4_ENCRYPT)
    {
        while (l--)
        {
            if (n == 0)
            {
                sm4_encrypt(iv, iv, round_key);
            }
            iv[n] = *(out++) = *(in++) ^ iv[n];
            n = (n + 1) % SM4_BLOCK_SIZE;
        }
    }
    else
    {
        while (l--)
        {
            if (n == 0)
            {
                sm4_encrypt(iv, iv, round_key);
            }
            c = *(in);
            *(out++) = *(in++) ^ iv[n];
            iv[n] = c;
            n = (n + 1) % SM4_BLOCK_SIZE;
        }
    }

}


void sm4_ofb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec)
{
    /*
    in:        要加密或解密的数据。
    out:       输出的结果
    length:    in的字节数
    key:       16 字节的用户密钥
    ivec:      16 字节的初始化向量
    */

    U32 n = 0;
    U32 l = length;
    U32 round_key[32];
    U8 iv[SM4_BLOCK_SIZE];

    if((in == NULL) || (out == NULL) || (key == NULL) || (ivec == NULL))
        return;


    sm4_set_key(key, round_key);
    memcpy(iv, ivec, SM4_BLOCK_SIZE);

    while (l--)
    {
        if (n == 0)
        {
            sm4_encrypt(iv, iv, round_key);
        }
        *(out++) = *(in++) ^ iv[n];
        n = (n + 1) % SM4_BLOCK_SIZE;
    }

}

#if 0

int main(void)
{

    U8 key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                            };
    U8 in[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                           };
    U8 check[16] = {0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F, 0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66};
    U8 out[16];
    U32 i;
    U32 j;
    U32 rk[32];
    U8 inbuf[10000], outbuf[10000], chkbuf[10000], iv[16];

    clock_t start, end;
    double tt;


    memset(inbuf, 'A', sizeof(inbuf));
    sm4_ofb_encrypt(inbuf, outbuf, sizeof(inbuf), key, in);
    sm4_ofb_encrypt(outbuf, chkbuf, sizeof(inbuf), key, in);

    start = clock();

    sm4_set_key(key, &rk[0]);

    for(j = 0; j < 1000000; j++)
    {

//	sm4_ecb_encrypt(inbuf, outbuf, 4096, key, SM4_ENCRYPT);


        sm4_encrypt(in, out, rk);
        memcpy(in, out, 16);
    }

    end = clock();

    tt = (double)(end - start) / CLOCKS_PER_SEC;
    printf("speed:%lfMbps\n", (double)128 / tt);
    //printf("speed:%lfMBps\n", (double)4096 / tt);

    printf("Encrypted: ");
    for(i = 0; i < 16; i++)
    {
        printf("%02X ", out[i] & 0xFF);
    }


    if(memcmp(out, check, 16) == 0 )
    {
        printf("\n### Test OK ###\n");
    }
    else
    {
        printf("### Test error ###\n");
        return -1;
    }


    srand( (unsigned)time( NULL ) );
    for(j = 0; j < 10000; j++)
    {
        for(i = 0; i < 16; i++)
        {
            key[i] = rand();
            in[i]  = rand();
        }

        sm4_set_key(key, &rk[0]);
        sm4_encrypt(in, out, rk);
        sm4_decrypt(out, check, rk);
        if(memcmp(in, check, 16) == 0)
        {
            printf("Test OK %d\r", j);
        }
        else
        {
            printf("Test error!\n");
            return -1;
        }

    }

    printf("\n");


    for(j = 0; j < sizeof(inbuf); j += 16)
    {
        for(i = 0; i < 16; i++)
        {
            key[i] = rand();
            iv[i]  = rand();
        }

        for(i = 0; i < sizeof(inbuf); i++)
            inbuf[i] = rand();

        sm4_ecb_encrypt(inbuf, outbuf, j, key, SM4_ENCRYPT);
        sm4_ecb_encrypt(outbuf, chkbuf, j, key, SM4_DECRYPT);

        if(memcmp(inbuf, chkbuf, j) == 0)
        {
            printf("ECB Test OK %d\r", j);
        }
        else
        {
            printf("ECB Test error %d\n", j);
            return -1;
        }

    }

    printf("\n");

    for(j = 1; j < sizeof(inbuf); j++)
    {
        for(i = 0; i < 16; i++)
        {
            key[i] = rand();
            iv[i]  = rand();
        }

        for(i = 0; i < sizeof(inbuf); i++)
            inbuf[i] = rand();

        sm4_cbc_encrypt(inbuf, outbuf, j, key, iv, SM4_ENCRYPT);
        sm4_cbc_encrypt(outbuf, chkbuf, j, key, iv, SM4_DECRYPT);

        if(memcmp(inbuf, chkbuf, j) == 0)
        {
            printf("CBC Test OK %d\r", j);
        }
        else
        {
            printf("CBC Test error %d\n", j);
            return -1;
        }


        sm4_cbc_mac(inbuf, chkbuf, j, key, iv);
        if(j % 16)
        {
            if(memcmp(outbuf + j - (j % 16), chkbuf, 16) == 0)
            {
                printf("MAC Test OK %d\r", j);
            }
            else
            {
                printf("MAC Test error %d\n", j);
                return -1;
            }
        }
        else
        {
            if(memcmp(outbuf + j - 16, chkbuf, 16) == 0)
            {
                printf("MAC Test OK %d\r", j);
            }
            else
            {
                printf("MAC Test error %d\n", j);
                return -1;
            }
        }
    }


    printf("\n");

    return 0;


}

#endif



