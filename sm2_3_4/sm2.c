#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include "sm2.h"


#define SM2_DEBUG   0


struct FPECC
{
    char *p;
    char *a;
    char *b;
    char *n;
    char *x;
    char *y;
};

#if SM2_DEBUG

void PrintBuf(unsigned char *buf, int	buflen)
{
    int i;
    printf("\n");
    printf("len = %d\n", buflen);
    for(i = 0; i < buflen; i++)
    {
        if (i % 32 != 31)
            printf("%02x", buf[i]);
        else
            printf("%02x\n", buf[i]);
    }
    printf("\n");
    return;
}


void PrintBig(miracl *mip, big data)
{
    int len = 0;
    unsigned char buf[10240];

    len = big_to_bytes(mip, 0, data, (char *)buf, 0);
    PrintBuf(buf, len);
}

unsigned char radom[]  = {0x6C, 0xB2, 0x8D, 0x99, 0x38, 0x5C, 0x17, 0x5C, 0x94, 0xF9, 0x4E, 0x93, 0x48, 0x17, 0x66, 0x3F, 0xC1, 0x76, 0xD9, 0x25, 0xDD, 0x72, 0xB7, 0x27, 0x26, 0x0D, 0xBA, 0xAE, 0x1F, 0xB2, 0xF9, 0x6F};
unsigned char radom1[] = {0x4C, 0x62, 0xEE, 0xFD, 0x6E, 0xCF, 0xC2, 0xB9, 0x5B, 0x92, 0xFD, 0x6C, 0x3D, 0x95, 0x75, 0x14, 0x8A, 0xFA, 0x17, 0x42, 0x55, 0x46, 0xD4, 0x90, 0x18, 0xE5, 0x38, 0x8D, 0x49, 0xDD, 0x7B, 0x4F};
unsigned char randkey[] = {0x83, 0xA2, 0xC9, 0xC8, 0xB9, 0x6E, 0x5A, 0xF7, 0x0B, 0xD4, 0x80, 0xB4, 0x72, 0x40, 0x9A, 0x9A, 0x32, 0x72, 0x57, 0xF1, 0xEB, 0xB7, 0x3F, 0x5B, 0x07, 0x33, 0x54, 0xB2, 0x48, 0x66, 0x85, 0x63};
unsigned char randkeyb[] = {0x33, 0xFE, 0x21, 0x94, 0x03, 0x42, 0x16, 0x1C, 0x55, 0x61, 0x9C, 0x4A, 0x0C, 0x06, 0x02, 0x93, 0xD5, 0x43, 0xC8, 0x0A, 0xF1, 0x97, 0x48, 0xCE, 0x17, 0x6D, 0x83, 0x47, 0x7D, 0xE7, 0x1C, 0x80};

struct FPECC Ecc256 =
{
    "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
    "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
    "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
    "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
    "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
    "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
};
unsigned char sm2_par_dig[128] =
{
    0x78, 0x79, 0x68, 0xB4, 0xFA, 0x32, 0xC3, 0xFD, 0x24, 0x17, 0x84, 0x2E, 0x73, 0xBB, 0xFE, 0xFF,
    0x2F, 0x3C, 0x84, 0x8B, 0x68, 0x31, 0xD7, 0xE0, 0xEC, 0x65, 0x22, 0x8B, 0x39, 0x37, 0xE4, 0x98,
    0x63, 0xE4, 0xC6, 0xD3, 0xB2, 0x3B, 0x0C, 0x84, 0x9C, 0xF8, 0x42, 0x41, 0x48, 0x4B, 0xFE, 0x48,
    0xF6, 0x1D, 0x59, 0xA5, 0xB1, 0x6B, 0xA0, 0x6E, 0x6E, 0x12, 0xD1, 0xDA, 0x27, 0xC5, 0x24, 0x9A,
    0x42, 0x1D, 0xEB, 0xD6, 0x1B, 0x62, 0xEA, 0xB6, 0x74, 0x64, 0x34, 0xEB, 0xC3, 0xCC, 0x31, 0x5E,
    0x32, 0x22, 0x0B, 0x3B, 0xAD, 0xD5, 0x0B, 0xDC, 0x4C, 0x4E, 0x6C, 0x14, 0x7F, 0xED, 0xD4, 0x3D,
    0x06, 0x80, 0x51, 0x2B, 0xCB, 0xB4, 0x2C, 0x07, 0xD4, 0x73, 0x49, 0xD2, 0x15, 0x3B, 0x70, 0xC4,
    0xE5, 0xD7, 0xFD, 0xFC, 0xBF, 0xA3, 0x6E, 0xA1, 0xA8, 0x58, 0x41, 0xB9, 0xE4, 0x6E, 0x09, 0xA2,
};

#else
/*SM2*/

struct FPECC Ecc256 =
{
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

unsigned char sm2_par_dig[128] =
{
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
};

#endif


#define SEED_CONST 0x1BD8C55A
unsigned int rand_count = 0;
unsigned int rand_seed = 0x1BD8C559;

unsigned char *sm3_e(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *msg, int msg_len, unsigned char *e)
{
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
    unsigned char *buf;
    int userid_bitlen;

    if((xa_len > 32) || (ya_len > 32))
        return NULL;

    buf = malloc(2 + userid_len + 128 + 32 + 32);
    if(buf == NULL)
        return NULL;

    userid_bitlen = userid_len << 3;
    buf[0] = (userid_bitlen >> 8) & 0xFF;
    buf[1] = userid_bitlen & 0xFF;

    memcpy(buf + 2, userid, userid_len);
    memcpy(buf + 2 + userid_len, sm2_par_dig, 128);

    memset(buf + 2 + userid_len + 128, 0, 64);
    memcpy(buf + 2 + userid_len + 128 + 32 - xa_len, xa, xa_len);
    memcpy(buf + 2 + userid_len + 128 + 32 + 32 - ya_len, ya, ya_len);

    sm3(buf, 2 + userid_len + 128 + 32 + 32, e);
    free(buf);

#if SM2_DEBUG
    printf("sm3_e: ");
    PrintBuf(e, 32);
#endif

    buf = malloc(msg_len + 32);
    if(buf == NULL)
        return NULL;

    memcpy(buf, e, 32);
    memcpy(buf + 32, msg, msg_len);
    sm3(buf, 32 + msg_len, e);

    free(buf);

    return (e);

}


int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf)
{
    /*
    return 0: kbuf is 0, unusable
           1: kbuf is OK
    */
    unsigned char buf[70];
    unsigned char digest[32];
    unsigned int ct = 0x00000001;
    int i, m, n;
    unsigned char *p;


    memcpy(buf, zl, 32);
    memcpy(buf + 32, zr, 32);

    m = klen / 32;
    n = klen % 32;
    p = kbuf;

    for(i = 0; i < m; i++)
    {
        buf[64] = (ct >> 24) & 0xFF;
        buf[65] = (ct >> 16) & 0xFF;
        buf[66] = (ct >> 8) & 0xFF;
        buf[67] = ct & 0xFF;
        sm3(buf, 68, p);
        p += 32;
        ct++;
    }

    if(n != 0)
    {
        buf[64] = (ct >> 24) & 0xFF;
        buf[65] = (ct >> 16) & 0xFF;
        buf[66] = (ct >> 8) & 0xFF;
        buf[67] = ct & 0xFF;
        sm3(buf, 68, digest);
    }

    memcpy(p, digest, n);

    for(i = 0; i < klen; i++)
    {
        if(kbuf[i] != 0)
            break;
    }

    if(i < klen)
        return 1;
    else
        return 0;

}



int sm3_z(unsigned char *userid, int userid_len, unsigned char *xa, int xa_len, unsigned char *ya, int ya_len, unsigned char *z)
{
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
    unsigned char *buf;
    int userid_bitlen;

    if((xa_len > 32) || (ya_len > 32))
        return -1;

    buf = malloc(2 + userid_len + 128 + 32 + 32);
    if(buf == NULL)
        return -1;

    userid_bitlen = userid_len << 3;
    buf[0] = (userid_bitlen >> 8) & 0xFF;
    buf[1] = userid_bitlen & 0xFF;

    memcpy(buf + 2, userid, userid_len);
    memcpy(buf + 2 + userid_len, sm2_par_dig, 128);

    memset(buf + 2 + userid_len + 128, 0, 64);
    memcpy(buf + 2 + userid_len + 128 + 32 - xa_len, xa, 32);
    memcpy(buf + 2 + userid_len + 128 + 32 + 32 - ya_len, ya, 32);

    sm3(buf, 2 + userid_len + 128 + 32 + 32, z);
    free(buf);

#if SM2_DEBUG
    printf("sm3_z: ");
    PrintBuf(z, 32);
#endif

    return 0;

}


int kdf_key(unsigned char *z, int zlen, int klen, unsigned char *kbuf)
{
    /*
    return 0: kbuf is 0, unusable
           1: kbuf is OK
    */
    unsigned char *buf;
    unsigned char digest[32];
    unsigned int ct = 0x00000001;
    int i, m, n;
    unsigned char *p;

    buf = malloc(zlen + 4);
    if(buf == NULL)
        return 0;

    memcpy(buf, z, zlen);

    m = klen / 32;
    n = klen % 32;
    p = kbuf;

    for(i = 0; i < m; i++)
    {
        buf[zlen] = (ct >> 24) & 0xFF;
        buf[zlen + 1] = (ct >> 16) & 0xFF;
        buf[zlen + 2] = (ct >> 8) & 0xFF;
        buf[zlen + 3] = ct & 0xFF;
        sm3(buf, zlen + 4, p);
        p += 32;
        ct++;
    }

    if(n != 0)
    {
        buf[zlen] = (ct >> 24) & 0xFF;
        buf[zlen + 1] = (ct >> 16) & 0xFF;
        buf[zlen + 2] = (ct >> 8) & 0xFF;
        buf[zlen + 3] = ct & 0xFF;
        sm3(buf, zlen + 4, digest);
    }

    memcpy(p, digest, n);

    free(buf);

    return 1;

}

/********************************************************/
//               以下是P域上的ECC函数                   //
/*******************************************************/

#ifdef MR_STATIC

#if MIRACL == 32
#if SM2_DEBUG
#include "sm2_32_debug_table.h"
#else
#include "sm2_32_table.h"
#endif
#else
#if SM2_DEBUG
#include "sm2_64_debug_table.h"
#else
#include "sm2_64_table.h"
#endif
#endif


#define HEXDIGS (MIRACL/2)   /* !!!! #define MR_STATIC 16 for x86_32, 8 for x86_64 !!!! */

int sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, int *wylen, unsigned char *privkey, int *privkeylen)
{
    /*
    功能：生成SM2公私钥对
    [输出] wx：   公钥的X坐标，不足32字节在前面加0x00
    [输出] wxlen: wx的字节数，32
    [输出] wy：   公钥的Y坐标，不足32字节在前面加0x00
    [输出] wylen: wy的字节数，32
    [输出] privkey：私钥，不足32字节在前面加0x00
    [输出] privkeylen： privkey的字节数，32
    */

    big p, a, b, n, k, pa, pb;
    int promptr;
    ebrick binst;
    miracl instance;
    miracl *mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    char mem_big[MR_BIG_RESERVE(7)];


    mip->IOBASE = 16;

    memset(mem_big, 0, MR_BIG_RESERVE(7));

    p = mirvar_mem(mip, mem_big, 0);
    a = mirvar_mem(mip, mem_big, 1);
    b = mirvar_mem(mip, mem_big, 2);
    n = mirvar_mem(mip, mem_big, 3);
    k = mirvar_mem(mip, mem_big, 4);
    pa = mirvar_mem(mip, mem_big, 5);
    pb = mirvar_mem(mip, mem_big, 6);


    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);

    ebrick_init(&binst, prom, a, b, p, WINDOW, CURVE_BITS);

    if(rand_count == 0)
    {
        rand_seed = time(NULL) + SEED_CONST + getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(mip, rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(mip, rand_seed);
    }

    do
    {
        bigrand(mip, n, k);

    }
    while(k->len == 0);


    mul_brick(mip, &binst, k, pa, pb); /* k*G => (pa,pb) */


    *wxlen = big_to_bytes(mip, 32, pa, (char *)wx, TRUE);
    *wylen = big_to_bytes(mip, 32, pb, (char *)wy, TRUE);
    *privkeylen = big_to_bytes(mip, 32, k, (char *)privkey, TRUE);

    mirexit(mip);

    return 1;

}

int sm2_sign(unsigned char *hash, int hashlen, unsigned char *privkey, int privkeylen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen)
{
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
    */

    big p, a, b, n, x, y, d, r, s, k, e;
    int promptr;
    epoint *g;
    ebrick binst;
    miracl instance;
    miracl *mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    char mem[MR_BIG_RESERVE(11)];
    char mem_ecp[MR_ECP_RESERVE(1)];


    mip->IOBASE = 16;
    memset(mem, 0, MR_BIG_RESERVE(11));
    memset(mem_ecp, 0, MR_ECP_RESERVE(1));

    p = mirvar_mem(mip, mem, 0);
    a = mirvar_mem(mip, mem, 1);
    b = mirvar_mem(mip, mem, 2);
    n = mirvar_mem(mip, mem, 3);
    x = mirvar_mem(mip, mem, 4);
    y = mirvar_mem(mip, mem, 5);
    d = mirvar_mem(mip, mem, 6);
    r = mirvar_mem(mip, mem, 7);
    s = mirvar_mem(mip, mem, 8);
    k = mirvar_mem(mip, mem, 9);
    e = mirvar_mem(mip, mem, 10);


    g = epoint_init_mem(mip, mem_ecp, 0);

    if(rand_count == 0)
    {
        rand_seed = time(NULL) + SEED_CONST + getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(mip, rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(mip, rand_seed);
    }


    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);


    ebrick_init(&binst, prom, a, b, p, WINDOW, CURVE_BITS);

    bytes_to_big(mip, hashlen, (char *)hash, e);
    bytes_to_big(mip, privkeylen, (char *)privkey, d);


sm2_sign_again:


#if SM2_DEBUG
    bytes_to_big(mip, 32, (char *)radom, k);
#else
    do
    {
        bigrand(mip, n, k);

    }
    while(k->len == 0);
#endif


    mul_brick(mip, &binst, k, r, r);

#if SM2_DEBUG
    printf("%s: %d\n", __FILE__, __LINE__);
    PrintBig(mip, r);
#endif


    add(mip, e, r, r);
    divide(mip, r, n, n);


    if(r->len == 0)
        goto sm2_sign_again;


    add(mip, r, k, x);
    if (compare(x, n) == 0)
        goto sm2_sign_again;


    incr(mip, d, 1, y);
    xgcd(mip, y, n, y, y, y);


    multiply(mip, r, d, x);
    divide(mip, x, n, n);

    if(compare(k, x) >= 0)
    {
        subtract(mip, k, x, x);
    }
    else
    {
        subtract(mip, n, x, x);
        add(mip, k, x, x);
    }

    mad(mip, x, y, x, n, n, s);

#if SM2_DEBUG
    printf("%s: %d\n", __FILE__, __LINE__);
    PrintBig(mip, r);
    PrintBig(mip, s);
#endif

    if(s->len == 0)
        goto sm2_sign_again;


    *rlen = big_to_bytes(mip, 32, r, (char *)cr, TRUE);
    *slen = big_to_bytes(mip, 32, s, (char *)cs, TRUE);

    mirexit(mip);

    return 1;


}



int sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen)
{
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


    int ret = 0;
    big p, a, b, n, x, y, e, r, s, t, v, z;
    int promptr;
    epoint *g, *w;
    ebrick binst;
    miracl instance;
    miracl *mip = mirsys(&instance, WORDS * HEXDIGS, 16);

    char mem[MR_BIG_RESERVE(12)];
    char mem_ecp[MR_ECP_RESERVE(2)];



    mip->IOBASE = 16;

    memset(mem, 0, MR_BIG_RESERVE(12));
    memset(mem_ecp, 0, MR_ECP_RESERVE(2));

    p = mirvar_mem(mip, mem, 0);
    a = mirvar_mem(mip, mem, 1);
    b = mirvar_mem(mip, mem, 2);
    n = mirvar_mem(mip, mem, 3);
    x = mirvar_mem(mip, mem, 4);
    y = mirvar_mem(mip, mem, 5);
    e = mirvar_mem(mip, mem, 6);
    r = mirvar_mem(mip, mem, 7);
    s = mirvar_mem(mip, mem, 8);
    t = mirvar_mem(mip, mem, 9);
    v = mirvar_mem(mip, mem, 10);
    z = mirvar_mem(mip, mem, 11);


    g = epoint_init_mem(mip, mem_ecp, 0);
    w = epoint_init_mem(mip, mem_ecp, 1);


    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);


    ecurve_init(mip, a, b, p, MR_PROJECTIVE);
    bytes_to_big(mip, wxlen, (char *)wx, x);
    bytes_to_big(mip, wylen, (char *)wy, y);
    if(!epoint_set(mip, x, y, 0, w))
        goto exit_sm2_verify;

    bytes_to_big(mip, hashlen, (char *)hash, e);
    bytes_to_big(mip, rlen, (char *)cr, r);
    bytes_to_big(mip, slen, (char *)cs, s);

    if ((compare(r, n) >= 0)  || (r->len == 0))
        goto exit_sm2_verify;

    if ((compare(s, n) >= 0) || (s->len == 0))
        goto exit_sm2_verify;


    add(mip, s, r, t);         // r + s mod n => t
    divide(mip, t, n, n);
    if (t->len == 0)
        goto exit_sm2_verify;

    ecurve_mult(mip, t, w, w);  // t * P(x,y) => w

#if SM2_DEBUG
    PrintBig(mip, t);
#endif

    ebrick_init(&binst, prom, a, b, p, WINDOW, CURVE_BITS);
    mul_brick(mip, &binst, s, x, y);   // s * G => g

#if SM2_DEBUG
    PrintBig(mip, x);
    PrintBig(mip, y);
#endif

    epoint_set(mip, x, y, 0, g);
    ecurve_add(mip, w, g);           // w + g => g
    epoint_get(mip, g, v, v);

#if SM2_DEBUG
    PrintBig(mip, v);
#endif

    add(mip, v, e, v);
    divide(mip, v, n, n);

#if SM2_DEBUG
    PrintBig(mip, v);
#endif

    if (compare(v, r) == 0)
        ret = 1;


exit_sm2_verify:
    mirexit(mip);
    return ret;


}


int sm2_encrypt(unsigned char *msg, int msglen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen, unsigned char *outmsg)
{
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

    big p, a, b, n, x, y;
    big x2, y2, c1, c2, k;
    int promptr;

    epoint *g, *w;
    int ret = -1;
    int i;
    unsigned char zl[32], zr[32];
    unsigned char *tmp;

    ebrick binst;
    miracl instance;
    miracl *mip;
    char mem[MR_BIG_RESERVE(11)];
    char mem_ecp[MR_ECP_RESERVE(2)];


    tmp = malloc(msglen + 64);
    if(tmp == NULL)
    {
        return -1;
    }

    mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    mip->IOBASE = 16;

    memset(mem, 0, MR_BIG_RESERVE(11));
    memset(mem_ecp, 0, MR_ECP_RESERVE(2));

    p = mirvar_mem(mip, mem, 0);
    a = mirvar_mem(mip, mem, 1);
    b = mirvar_mem(mip, mem, 2);
    n = mirvar_mem(mip, mem, 3);
    x = mirvar_mem(mip, mem, 4);
    y = mirvar_mem(mip, mem, 5);
    x2 = mirvar_mem(mip, mem, 6);
    y2 = mirvar_mem(mip, mem, 7);
    c1 = mirvar_mem(mip, mem, 8);
    c2 = mirvar_mem(mip, mem, 9);
    k = mirvar_mem(mip, mem, 10);


    g = epoint_init_mem(mip, mem_ecp, 0);
    w = epoint_init_mem(mip, mem_ecp, 1);

    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);

    ebrick_init(&binst, prom, a, b, p, WINDOW, CURVE_BITS);
    ecurve_init(mip, a, b, p, MR_PROJECTIVE);

    bytes_to_big(mip, wxlen, (char *)wx, x);
    bytes_to_big(mip, wylen, (char *)wy, y);
    epoint_set(mip, x, y, 0, w);
    if(point_at_infinity(w))
        goto exit_sm2_encrypt;

    if(rand_count == 0)
    {
        rand_seed = time(NULL) + SEED_CONST + getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(mip, rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(mip, rand_seed);
    }

sm2_encrypt_again:

#if SM2_DEBUG
    bytes_to_big(mip, 32, (char *)radom1, k);
#else
    do
    {
        bigrand(mip, n, k);
    }
    while(k->len == 0);
#endif

    mul_brick(mip, &binst, k, c1, c2);

    big_to_bytes(mip, 32, c1, (char *)outmsg, TRUE);
    big_to_bytes(mip, 32, c2, (char *)outmsg + 32, TRUE);

#if SM2_DEBUG
    printf("sm2_encrypt 1\n");
    PrintBig(mip, c1);
    printf("sm2_encrypt 2\n");
    PrintBig(mip, c2);
#endif


    ecurve_mult(mip, k, w, w);
    epoint_get(mip, w, x2, y2);

#if SM2_DEBUG
    PrintBig(mip, x2);
    PrintBig(mip, y2);
#endif

    big_to_bytes(mip, 32, x2, (char *)zl, TRUE);
    big_to_bytes(mip, 32, y2, (char *)zr, TRUE);

    if (kdf(zl, zr, msglen, outmsg + 64) == 0)
        goto sm2_encrypt_again;

    for(i = 0; i < msglen; i++)
    {
        outmsg[64 + i] ^= msg[i];
    }


    memcpy(tmp, zl, 32);
    memcpy(tmp + 32, msg, msglen);
    memcpy(tmp + 32 + msglen, zr, 32);

    sm3(tmp, 64 + msglen, &outmsg[64 + msglen]);

    ret = msglen + 64 + 32;

exit_sm2_encrypt:


    free(tmp);

    mirexit(mip);

    return ret;

}

int sm2_decrypt(unsigned char *msg, int msglen, unsigned char *privkey, int privkeylen, unsigned char *outmsg)
{
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
    big x2, y2, c, k, key1;
    big p, a, b, x, y;
    int promptr;
    epoint *g;

    unsigned char c3[32];
    unsigned char zl[32], zr[32];
    int i, ret = -1;
    unsigned char *tmp;

    miracl instance;
    miracl *mip;
    char mem[MR_BIG_RESERVE(10)];
    char mem_ecp[MR_ECP_RESERVE(1)];

    if(msglen < 96)
        return 0;

    msglen -= 96;

    tmp = malloc(msglen + 64);
    if(tmp == NULL)
        return 0;

    memset(mem, 0, MR_BIG_RESERVE(10));
    memset(mem_ecp, 0, MR_ECP_RESERVE(1));

    mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    mip->IOBASE = 16;


    p = mirvar_mem(mip, mem, 0);
    a = mirvar_mem(mip, mem, 1);
    b = mirvar_mem(mip, mem, 2);
    x = mirvar_mem(mip, mem, 3);
    y = mirvar_mem(mip, mem, 4);
    x2 = mirvar_mem(mip, mem, 5);
    y2 = mirvar_mem(mip, mem, 6);
    c = mirvar_mem(mip, mem, 7);
    k = mirvar_mem(mip, mem, 8);
    key1 = mirvar_mem(mip, mem, 9);

    g = epoint_init_mem(mip, mem_ecp, 0);


    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);

    bytes_to_big(mip, privkeylen, (char *)privkey, key1);
    bytes_to_big(mip, 32, (char *)msg, x);
    bytes_to_big(mip, 32, (char *)msg + 32, y);

    ecurve_init(mip, a, b, p, MR_PROJECTIVE);
    if(!epoint_set(mip, x, y, 0, g))
        goto exit_sm2_decrypt;

    if(point_at_infinity(g))
        goto exit_sm2_decrypt;

    ecurve_mult(mip, key1, g, g);
    epoint_get(mip, g, x2, y2);

#if SM2_DEBUG
    printf("sm2_decrypt 1\n");
    PrintBig(mip, x2);
    printf("sm2_decrypt 2\n");
    PrintBig(mip, y2);
#endif

    big_to_bytes(mip, 32, x2, (char *)zl, TRUE);
    big_to_bytes(mip, 32, y2, (char *)zr, TRUE);

    if (kdf(zl, zr, msglen, outmsg) == 0)
        goto exit_sm2_decrypt;

    for(i = 0; i < msglen; i++)
    {
        outmsg[i] ^= msg[i + 64];
    }

    memcpy(tmp, zl, 32);
    memcpy(tmp + 32, outmsg, msglen);
    memcpy(tmp + 32 + msglen, zr, 32);

    sm3(tmp, 64 + msglen, c3);
#if SM2_DEBUG
    printf("sm2_decrypt 3\n");
    PrintBuf(c3, 32);
#endif

    if(memcmp(c3, msg + 64 + msglen, 32) != 0)
        goto exit_sm2_decrypt;

    ret =  msglen;

exit_sm2_decrypt:

    mirexit(mip);
    free(tmp);

    return ret;
}

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
)
{
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

    big k, x1, y1, x2, y2, _x1, _x2, da, ta;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = 0;
    unsigned char kx1buf[32], ky1buf[32];
    unsigned char kx2buf[32], ky2buf[32];
    unsigned char xubuf[32];
    unsigned char yubuf[32];
    unsigned char buf[256];

    unsigned char za[32];
    unsigned char zb[32];
    unsigned char hash[32];

    int promptr;
    miracl instance;
    miracl *mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    char mem[MR_BIG_RESERVE(15)];
    char mem_ecp[MR_ECP_RESERVE(2)];



    mip->IOBASE = 16;
    memset(mem, 0, MR_BIG_RESERVE(15));
    memset(mem_ecp, 0, MR_ECP_RESERVE(2));

    p  = mirvar_mem(mip, mem, 0);
    a  = mirvar_mem(mip, mem, 1);
    b  = mirvar_mem(mip, mem, 2);
    n  = mirvar_mem(mip, mem, 3);
    x  = mirvar_mem(mip, mem, 4);
    y  = mirvar_mem(mip, mem, 5);
    k  = mirvar_mem(mip, mem, 6);
    x1 = mirvar_mem(mip, mem, 7);
    y1 = mirvar_mem(mip, mem, 8);
    x2 = mirvar_mem(mip, mem, 9);
    y2 = mirvar_mem(mip, mem, 10);
    _x1 = mirvar_mem(mip, mem, 11);
    _x2 = mirvar_mem(mip, mem, 12);
    ta = mirvar_mem(mip, mem, 13);
    da = mirvar_mem(mip, mem, 14);

    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);

    ecurve_init(mip, a, b, p, MR_PROJECTIVE);
    g = epoint_init_mem(mip, mem_ecp, 0);
    w = epoint_init_mem(mip, mem_ecp, 1);


    sm3_z(ida, idalen, xa, xalen, ya, yalen, za);
    sm3_z(idb, idblen, xb, xblen, yb, yblen, zb);


    bytes_to_big(mip, kxalen, (char *)kxa, x1);
    bytes_to_big(mip, kyalen, (char *)kya, y1);

    if(!epoint_set(mip, x1, y1, 0, g))
        goto exit_sm2_keyagreement_a;

    big_to_bytes(mip, 32, x1, (char *)kx1buf, TRUE);
    big_to_bytes(mip, 32, y1, (char *)ky1buf, TRUE);
    memcpy(buf, kx1buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(mip, 16, (char *)buf, _x1);
#if SM2_DEBUG
    PrintBig(mip, _x1);
#endif


    bytes_to_big(mip, private_a_len, (char *)private_a, da);

    bytes_to_big(mip, private_a_tmp_len, (char *)private_a_tmp, k);

    mad(mip, _x1, k, da, n, n, ta);

#if SM2_DEBUG
    PrintBig(mip, ta);
#endif


    bytes_to_big(mip, kxblen, (char *)kxb, x2);
    bytes_to_big(mip, kyblen, (char *)kyb, y2);
    if(!epoint_set(mip, x2, y2, 0, g))
        goto exit_sm2_keyagreement_a;

    big_to_bytes(mip, 32, x2, (char *)kx2buf, TRUE);
    big_to_bytes(mip, 32, y2, (char *)ky2buf, TRUE);
    memcpy(buf, kx2buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(mip, 16, (char *)buf, _x2);

#if SM2_DEBUG
    PrintBig(mip, _x2);
#endif

    bytes_to_big(mip, xblen, (char *)xb, x);
    bytes_to_big(mip, yblen, (char *)yb, y);
    if(!epoint_set(mip, x, y, 0, w))
        goto exit_sm2_keyagreement_a;

    ecurve_mult(mip, _x2, g, g);
    ecurve_add(mip, w, g);
    ecurve_mult(mip, ta, g, g);
    if(point_at_infinity(g))
        goto exit_sm2_keyagreement_a;


    epoint_get(mip, g, x, y);
    big_to_bytes(mip, 32, x, (char *)xubuf, TRUE);
    big_to_bytes(mip, 32, y, (char *)yubuf, TRUE);

#if SM2_DEBUG
    printf("xu & yu: ");
    PrintBuf(xubuf, 32);
    PrintBuf(yubuf, 32);
#endif

    memcpy(buf, xubuf, 32);
    memcpy(buf + 32, yubuf, 32);
    memcpy(buf + 64, za, 32);
    memcpy(buf + 96, zb, 32);
    kdf_key(buf, 128, keylen, keybuf);

#if SM2_DEBUG
    printf("buf: ");
    PrintBuf(buf, 128);
    printf("Ka: ");
    PrintBuf(keybuf, keylen);
#endif

    if((s1 != NULL) || (sa != NULL))
    {
        memcpy(buf, xubuf, 32);
        memcpy(buf + 32, za, 32);
        memcpy(buf + 64, zb, 32);
        memcpy(buf + 96, kx1buf, 32);
        memcpy(buf + 128, ky1buf, 32);
        memcpy(buf + 160, kx2buf, 32);
        memcpy(buf + 192, ky2buf, 32);
        sm3(buf, 32 * 7, hash);
    }

    if(s1 != NULL)
    {
        buf[0] = 0x02;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, s1);
    }

    if(sa != NULL)
    {
        buf[0] = 0x03;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, sa);
    }

    ret = 1;

exit_sm2_keyagreement_a:

    mirexit(mip);

    return ret;
}

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
)
{
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

    big k, x1, y1, x2, y2, _x1, _x2, da, ta;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = 0;
    unsigned char kx1buf[32], ky1buf[32];
    unsigned char kx2buf[32], ky2buf[32];
    unsigned char xubuf[32];
    unsigned char yubuf[32];
    unsigned char buf[256];

    unsigned char za[32];
    unsigned char zb[32];
    unsigned char hash[32];


    int promptr;
    miracl instance;
    miracl *mip = mirsys(&instance, WORDS * HEXDIGS, 16);
    char mem[MR_BIG_RESERVE(15)];
    char mem_ecp[MR_ECP_RESERVE(2)];



    mip->IOBASE = 16;
    memset(mem, 0, MR_BIG_RESERVE(15));
    memset(mem_ecp, 0, MR_ECP_RESERVE(2));

    p  = mirvar_mem(mip, mem, 0);
    a  = mirvar_mem(mip, mem, 1);
    b  = mirvar_mem(mip, mem, 2);
    n  = mirvar_mem(mip, mem, 3);
    x  = mirvar_mem(mip, mem, 4);
    y  = mirvar_mem(mip, mem, 5);
    k  = mirvar_mem(mip, mem, 6);
    x1 = mirvar_mem(mip, mem, 7);
    y1 = mirvar_mem(mip, mem, 8);
    x2 = mirvar_mem(mip, mem, 9);
    y2 = mirvar_mem(mip, mem, 10);
    _x1 = mirvar_mem(mip, mem, 11);
    _x2 = mirvar_mem(mip, mem, 12);
    ta = mirvar_mem(mip, mem, 13);
    da = mirvar_mem(mip, mem, 14);


    promptr = 0;
    init_big_from_rom(p, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(a, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(b, WORDS, rom, WORDS * 8, &promptr);
    init_big_from_rom(n, WORDS, rom, WORDS * 8, &promptr);

    ecurve_init(mip, a, b, p, MR_PROJECTIVE);
    g = epoint_init_mem(mip, mem_ecp, 0);
    w = epoint_init_mem(mip, mem_ecp, 1);


    sm3_z(ida, idalen, xa, xalen, ya, yalen, za);
    sm3_z(idb, idblen, xb, xblen, yb, yblen, zb);


    bytes_to_big(mip, kxblen, (char *)kxb, x1);
    bytes_to_big(mip, kyblen, (char *)kyb, y1);

    if(!epoint_set(mip, x1, y1, 0, g))
        goto exit_sm2_keyagreement_b;

    big_to_bytes(mip, 32, x1, (char *)kx1buf, TRUE);
    big_to_bytes(mip, 32, y1, (char *)ky1buf, TRUE);
    memcpy(buf, kx1buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(mip, 16, (char *)buf, _x1);

#if SM2_DEBUG
    PrintBig(mip, _x1);
#endif


    bytes_to_big(mip, private_b_len, (char *)private_b, da);
    bytes_to_big(mip, private_b_tmp_len, (char *)private_b_tmp, k);

    mad(mip, _x1, k, da, n, n, ta);

#if SM2_DEBUG
    PrintBig(mip, ta);
#endif

    bytes_to_big(mip, kxalen, (char *)kxa, x2);
    bytes_to_big(mip, kyalen, (char *)kya, y2);
    if(!epoint_set(mip, x2, y2, 0, g))
        goto exit_sm2_keyagreement_b;

    big_to_bytes(mip, 32, x2, (char *)kx2buf, TRUE);
    big_to_bytes(mip, 32, y2, (char *)ky2buf, TRUE);
    memcpy(buf, kx2buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(mip, 16, (char *)buf, _x2);

#if SM2_DEBUG
    PrintBig(mip, _x2);
#endif

    bytes_to_big(mip, xalen, (char *)xa, x);
    bytes_to_big(mip, yalen, (char *)ya, y);
    if(!epoint_set(mip, x, y, 0, w))
        goto exit_sm2_keyagreement_b;

    ecurve_mult(mip, _x2, g, g);
    ecurve_add(mip, w, g);
    ecurve_mult(mip, ta, g, g);
    if(point_at_infinity(g))
        goto exit_sm2_keyagreement_b;


    epoint_get(mip, g, x, y);
    big_to_bytes(mip, 32, x, (char *)xubuf, TRUE);
    big_to_bytes(mip, 32, y, (char *)yubuf, TRUE);

#if SM2_DEBUG
    printf("xu & yu: ");
    PrintBuf(xubuf, 32);
    PrintBuf(yubuf, 32);
#endif


    memcpy(buf, xubuf, 32);
    memcpy(buf + 32, yubuf, 32);
    memcpy(buf + 64, za, 32);
    memcpy(buf + 96, zb, 32);
    kdf_key(buf, 128, keylen, keybuf);

#if SM2_DEBUG
    printf("buf: ");
    PrintBuf(buf, 128);
    printf("Kb: ");
    PrintBuf(keybuf, keylen);
#endif

    if((s2 != NULL) || (sb != NULL))
    {
        memcpy(buf, xubuf, 32);
        memcpy(buf + 32, za, 32);
        memcpy(buf + 64, zb, 32);
        memcpy(buf + 96, kx2buf, 32);
        memcpy(buf + 128, ky2buf, 32);
        memcpy(buf + 160, kx1buf, 32);
        memcpy(buf + 192, ky1buf, 32);
        sm3(buf, 32 * 7, hash);
    }

    if(s2 != NULL)
    {
        buf[0] = 0x03;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, s2);
    }

    if(sb != NULL)
    {
        buf[0] = 0x02;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, sb);
    }

    ret = 1;

exit_sm2_keyagreement_b:

    mirexit(mip);

    return ret;
}



#else


#ifdef MR_GENERIC_MT

#define mirvar(a)                mirvar(mip,a)
#define cinstr(a,b)              cinstr(mip,a,b)
#define ecurve_init(a,b,c,d)     ecurve_init(mip,a,b,c,d)
#define epoint_set(a,b,c,d)      epoint_set(mip,a,b,c,d)
#define big_to_bytes(a,b,c,d)    big_to_bytes(mip,a,b,c,d)
#define mirexit()                mirexit(mip)
#define bytes_to_big(a,b,c)      bytes_to_big(mip,a,b,c)
#define irand(a)                 irand(mip,a)
#define bigrand(a,b)             bigrand(mip,a,b)
#define ecurve_mult(a,b,c)       ecurve_mult(mip,a,b,c)
#define epoint_get(a,b,c)        epoint_get(mip,a,b,c)
#define divide(a,b,c)            divide(mip,a,b,c)
#define add(a,b,c)               add(mip,a,b,c)
#define epoint_init()            epoint_init(mip)
#define incr(a,b,c)              incr(mip,a,b,c)
#define xgcd(a,b,c,d,e)          xgcd(mip,a,b,c,d,e)
#define multiply(a,b,c)          multiply(mip,a,b,c)
#define fft_mult(a,b,c)          fft_mult(mip,a,b,c)
#define subtract(a,b,c)          subtract(mip,a,b,c)
#define mad(a,b,c,d,e,f)         mad(mip,a,b,c,d,e,f)
#define ecurve_add(a,b)          ecurve_add(mip,a,b)
#define ecurve_mult2(a,b,c,d,e)  ecurve_mult2(mip,a,b,c,d,e)

#endif

int sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, int *wylen, unsigned char *privkey, int *privkeylen)
{
    /*
    功能：生成SM2公私钥对
    [输出] wx：   公钥的X坐标，不足32字节在前面加0x00
    [输出] wxlen: wx的字节数，32
    [输出] wy：   公钥的Y坐标，不足32字节在前面加0x00
    [输出] wylen: wy的字节数，32
    [输出] privkey：私钥，不足32字节在前面加0x00
    [输出] privkeylen： privkey的字节数，32
    */

    struct FPECC *cfig = &Ecc256;
    epoint *g;
    big a, b, p, n, x, y, key1;
    miracl *mip = mirsys(20, 0);

    mip->IOBASE = 16;

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);

    key1 = mirvar(0);

    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);

    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    epoint_set(x, y, 0, g);

    if(rand_count == 0)
    {
        rand_seed = (unsigned int)time(NULL) + SEED_CONST + (unsigned int)getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(rand_seed);
    }

    bigrand(n, key1);
    ecurve_mult(key1, g, g);
    epoint_get(g, x, y);

    *wxlen = big_to_bytes(32, x, (char *)wx, TRUE);
    *wylen = big_to_bytes(32, y, (char *)wy, TRUE);
    *privkeylen = big_to_bytes(32, key1, (char *)privkey, TRUE);

    mirkill(key1);
    mirkill(p);
    mirkill(a);
    mirkill(b);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    epoint_free(g);
    mirexit();

    return 1;



}

int sm2_sign(unsigned char *hash, int hashlen, unsigned char *privkey, int privkeylen, unsigned char *cr, int *rlen, unsigned char *cs, int *slen)
{
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
    */


    struct FPECC *cfig = &Ecc256;
    big e, r, s, k;
    big a, b, p, n, x, y, key1;
    epoint *g;
    miracl *mip = mirsys(20, 0);

    mip->IOBASE = 16;
    e = mirvar(0);
    r = mirvar(0);
    s = mirvar(0);
    k = mirvar(0);

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);

    key1 = mirvar(0);
    bytes_to_big(privkeylen, (char *)privkey, key1);

    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);
    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    epoint_set(x, y, 0, g);

    bytes_to_big(hashlen, (char *)hash, e);
    if(rand_count == 0)
    {
        rand_seed = time(NULL) + SEED_CONST + getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(rand_seed);
    }

sm2_sign_again:
#if SM2_DEBUG
    bytes_to_big(32, (char *)radom, k);
#else
    do
    {
        bigrand(n, k);
    }
    while(k->len == 0);
#endif

    ecurve_mult(k, g, g);
    epoint_get(g, r, r);

#if SM2_DEBUG
    PrintBig(mip, r);
#endif

    add(e, r, r);
    divide(r, n, n);

#if SM2_DEBUG
    PrintBig(mip, r);
#endif

    if(r->len == 0)
        goto sm2_sign_again;

    add(r, k, a);
    if (compare(a, n) == 0)
        goto sm2_sign_again;

    incr(key1, 1, b);
    xgcd(b, n, b, b, b);

#if SM2_DEBUG
    PrintBig(mip, b);
#endif

    multiply(r, key1, a);
    divide(a, n, n);

    if(compare(k, a) >= 0)
    {
        subtract(k, a, a);
    }
    else
    {
        subtract(n, a, a);
        add(k, a, a);
    }

    mad(a, b, a, n, n, s);
#if SM2_DEBUG
    PrintBig(mip, s);
#endif

    if(s->len == 0)
        goto sm2_sign_again;


    *rlen = big_to_bytes(32, r, (char *)cr, TRUE);
    *slen = big_to_bytes(32, s, (char *)cs, TRUE);

    mirkill(e);
    mirkill(r);
    mirkill(s);
    mirkill(k);
    mirkill(p);
    mirkill(a);
    mirkill(b);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    mirkill(key1);
    epoint_free(g);
    mirexit();

    return 1;


}



int sm2_verify(unsigned char *hash, int hashlen, unsigned char  *cr, int rlen, unsigned char *cs, int slen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen)
{
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


    struct FPECC *cfig = &Ecc256;
    big e, r, s, v;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = 0;
    miracl *mip = mirsys(20, 0);

    mip->IOBASE = 16;
    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);

    e = mirvar(0);
    r = mirvar(0);
    s = mirvar(0);
    v = mirvar(0);

    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);

    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    w = epoint_init();
    epoint_set(x, y, 0, g);
    bytes_to_big(wxlen, (char *)wx, x);
    bytes_to_big(wylen, (char *)wy, y);
    if(!epoint_set(x, y, 0, w))
        goto exit_sm2_verify;

    bytes_to_big(hashlen, (char *)hash, e);
    bytes_to_big(rlen, (char *)cr, r);
    bytes_to_big(slen, (char *)cs, s);

    if ((compare(r, n) >= 0)  || (r->len == 0))
        goto exit_sm2_verify;

    if ((compare(s, n) >= 0) || (s->len == 0))
        goto exit_sm2_verify;


    add(s, r, a);
    divide(a, n, n);
    if (a->len == 0)
        goto exit_sm2_verify;

#if SM2_DEBUG
    PrintBig(mip, a);
#endif

    ecurve_mult2(s, g, a, w, g);
    epoint_get(g, v, v);
#if SM2_DEBUG
    PrintBig(mip, v);
#endif


    add(v, e, v);
    divide(v, n, n);
#if SM2_DEBUG
    PrintBig(mip, v);
#endif

    if (compare(v, r) == 0)
        ret = 1;

exit_sm2_verify:

    mirkill(r);
    mirkill(s);
    mirkill(v);
    mirkill(e);
    mirkill(a);
    mirkill(b);
    mirkill(p);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    epoint_free(g);
    epoint_free(w);
    mirexit();

    return ret;


}




int sm2_encrypt(unsigned char *msg, int msglen, unsigned char *wx, int wxlen, unsigned char *wy, int wylen, unsigned char *outmsg)
{
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
    struct FPECC *cfig = &Ecc256;
    big x2, y2, c1, c2, k;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = -1;
    int i;
    unsigned char zl[32], zr[32];
    unsigned char *tmp;
    miracl *mip;


    tmp = malloc(msglen + 64);
    if(tmp == NULL)
        return -1;

    mip = mirsys(20, 0);
    mip->IOBASE = 16;

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);

    k = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    c1 = mirvar(0);
    c2 = mirvar(0);

    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);

    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    w = epoint_init();
    epoint_set(x, y, 0, g);
    bytes_to_big(wxlen, (char *)wx, x);
    bytes_to_big(wylen, (char *)wy, y);
    epoint_set(x, y, 0, w);

    if(rand_count == 0)
    {
        rand_seed = time(NULL) + SEED_CONST + getpid() + (unsigned int)mip;
        srand(rand_seed);
        irand(rand_seed + rand());
        rand_count = 1;
    }
    else
    {
        rand_seed += rand();
        irand(rand_seed);
    }

sm2_encrypt_again:

#if SM2_DEBUG
    bytes_to_big(32, (char *)radom1, k);
#else
    do
    {
        bigrand(n, k);
    }
    while(k->len == 0);
#endif

    ecurve_mult(k, g, g);
    epoint_get(g, c1, c2);
    big_to_bytes(32, c1, (char *)outmsg, TRUE);
    big_to_bytes(32, c2, (char *)outmsg + 32, TRUE);

#if SM2_DEBUG
    printf("sm2_encrypt 1\n");
    PrintBig(mip, c1);
    printf("sm2_encrypt 2\n");
    PrintBig(mip, c2);
#endif

    if(point_at_infinity(w))
        goto exit_sm2_encrypt;

    ecurve_mult(k, w, w);
    epoint_get(w, x2, y2);

#if SM2_DEBUG
    PrintBig(mip, x2);
    PrintBig(mip, y2);
#endif

    big_to_bytes(32, x2, (char *)zl, TRUE);
    big_to_bytes(32, y2, (char *)zr, TRUE);

    if (kdf(zl, zr, msglen, outmsg + 64) == 0)
        goto sm2_encrypt_again;

    for(i = 0; i < msglen; i++)
    {
        outmsg[64 + i] ^= msg[i];
    }


    memcpy(tmp, zl, 32);
    memcpy(tmp + 32, msg, msglen);
    memcpy(tmp + 32 + msglen, zr, 32);

    sm3(tmp, 64 + msglen, &outmsg[64 + msglen]);

    ret = msglen + 64 + 32;

exit_sm2_encrypt:

    mirkill(x2);
    mirkill(y2);
    mirkill(c1);
    mirkill(c2);
    mirkill(k);
    mirkill(a);
    mirkill(b);
    mirkill(p);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    epoint_free(g);
    epoint_free(w);
    mirexit();
    free(tmp);


    return ret;

}


int sm2_decrypt(unsigned char *msg, int msglen, unsigned char *privkey, int privkeylen, unsigned char *outmsg)
{
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
    struct FPECC *cfig = &Ecc256;
    big x2, y2, c, k;
    big a, b, p, x, y, key1;
    epoint *g;

    unsigned char c3[32];
    unsigned char zl[32], zr[32];
    int i, ret = -1;
    unsigned char *tmp;

    miracl *mip;

    if(msglen < 96)
        return 0;

    msglen -= 96;

    tmp = malloc(msglen + 64);
    if(tmp == NULL)
        return 0;

    mip = mirsys(20, 0);
    mip->IOBASE = 16;

    x2 = mirvar(0);
    y2 = mirvar(0);
    c = mirvar(0);
    k = mirvar(0);

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    key1 = mirvar(0);

    bytes_to_big(privkeylen, (char *)privkey, key1);
    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);
    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();

    bytes_to_big(32, (char *)msg, x);
    bytes_to_big(32, (char *)msg + 32, y);
    if(!epoint_set(x, y, 0, g))
        goto exit_sm2_decrypt;

    if(point_at_infinity(g))
        goto exit_sm2_decrypt;

    ecurve_mult(key1, g, g);
    epoint_get(g, x2, y2);

#if SM2_DEBUG
    printf("sm2_decrypt 1\n");
    PrintBig(mip, x2);
    printf("sm2_decrypt 2\n");
    PrintBig(mip, y2);
#endif

    big_to_bytes(32, x2, (char *)zl, TRUE);
    big_to_bytes(32, y2, (char *)zr, TRUE);

    if (kdf(zl, zr, msglen, outmsg) == 0)
        goto exit_sm2_decrypt;

    for(i = 0; i < msglen; i++)
    {
        outmsg[i] ^= msg[i + 64];
    }

    memcpy(tmp, zl, 32);
    memcpy(tmp + 32, outmsg, msglen);
    memcpy(tmp + 32 + msglen, zr, 32);

    sm3(tmp, 64 + msglen, c3);
#if SM2_DEBUG
    printf("sm2_decrypt 3\n");
    PrintBuf(c3, 32);
#endif

    if(memcmp(c3, msg + 64 + msglen, 32) != 0)
        goto exit_sm2_decrypt;

    ret =  msglen;

exit_sm2_decrypt:

    mirkill(x2);
    mirkill(y2);
    mirkill(c);
    mirkill(k);
    mirkill(p);
    mirkill(a);
    mirkill(b);
    mirkill(x);
    mirkill(y);
    mirkill(key1);
    epoint_free(g);
    mirexit();
    free(tmp);

    return ret;
}





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
)
{
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

    struct FPECC *cfig = &Ecc256;
    big k, x1, y1, x2, y2, _x1, _x2, da, ta;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = 0;
    unsigned char kx1buf[32], ky1buf[32];
    unsigned char kx2buf[32], ky2buf[32];
    unsigned char xubuf[32];
    unsigned char yubuf[32];
    unsigned char buf[256];

    unsigned char za[32];
    unsigned char zb[32];
    unsigned char hash[32];




    miracl *mip = mirsys(20, 0);

    mip->IOBASE = 16;
    k  = mirvar(0);
    x1 = mirvar(0);
    y1 = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    _x1 = mirvar(0);
    _x2 = mirvar(0);
    ta = mirvar(0);
    da = mirvar(0);

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);


    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);
    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    w = epoint_init();


    sm3_z(ida, idalen, xa, xalen, ya, yalen, za);
    sm3_z(idb, idblen, xb, xblen, yb, yblen, zb);


    bytes_to_big(kxalen, (char *)kxa, x1);
    bytes_to_big(kyalen, (char *)kya, y1);

    if(!epoint_set(x1, y1, 0, g))
        goto exit_sm2_keyagreement_a;

    big_to_bytes(32, x1, (char *)kx1buf, TRUE);
    big_to_bytes(32, y1, (char *)ky1buf, TRUE);
    memcpy(buf, kx1buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(16, (char *)buf, _x1);
#if SM2_DEBUG
    PrintBig(mip, _x1);
#endif


    bytes_to_big(private_a_len, (char *)private_a, da);

    bytes_to_big(private_a_tmp_len, (char *)private_a_tmp, k);



    mad(_x1, k, da, n, n, ta);
#if SM2_DEBUG
    PrintBig(mip, ta);
#endif



    bytes_to_big(kxblen, (char *)kxb, x2);
    bytes_to_big(kyblen, (char *)kyb, y2);
    if(!epoint_set(x2, y2, 0, g))
        goto exit_sm2_keyagreement_a;

    big_to_bytes(32, x2, (char *)kx2buf, TRUE);
    big_to_bytes(32, y2, (char *)ky2buf, TRUE);
    memcpy(buf, kx2buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(16, (char *)buf, _x2);
#if SM2_DEBUG
    PrintBig(mip, _x2);
#endif

    bytes_to_big(xblen, (char *)xb, x);
    bytes_to_big(yblen, (char *)yb, y);
    if(!epoint_set(x, y, 0, w))
        goto exit_sm2_keyagreement_a;

    ecurve_mult(_x2, g, g);
    ecurve_add(w, g);
    ecurve_mult(ta, g, g);
    if(point_at_infinity(g))
        goto exit_sm2_keyagreement_a;


    epoint_get(g, x, y);
    big_to_bytes(32, x, (char *)xubuf, TRUE);
    big_to_bytes(32, y, (char *)yubuf, TRUE);
#if SM2_DEBUG
    printf("xu & yu: ");
    PrintBuf(xubuf, 32);
    PrintBuf(yubuf, 32);
#endif


    memcpy(buf, xubuf, 32);
    memcpy(buf + 32, yubuf, 32);
    memcpy(buf + 64, za, 32);
    memcpy(buf + 96, zb, 32);
    kdf_key(buf, 128, keylen, keybuf);
#if SM2_DEBUG
    printf("buf: ");
    PrintBuf(buf, 128);

    printf("Ka: ");
    PrintBuf(keybuf, keylen);
#endif

    if((s1 != NULL) || (sa != NULL))
    {
        memcpy(buf, xubuf, 32);
        memcpy(buf + 32, za, 32);
        memcpy(buf + 64, zb, 32);
        memcpy(buf + 96, kx1buf, 32);
        memcpy(buf + 128, ky1buf, 32);
        memcpy(buf + 160, kx2buf, 32);
        memcpy(buf + 192, ky2buf, 32);
        sm3(buf, 32 * 7, hash);
    }

    if(s1 != NULL)
    {
        buf[0] = 0x02;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, s1);
    }

    if(sa != NULL)
    {
        buf[0] = 0x03;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, sa);
    }

    ret = 1;

exit_sm2_keyagreement_a:

    mirkill(k);
    mirkill(x1);
    mirkill(y1);
    mirkill(x2);
    mirkill(y2);
    mirkill(_x1);
    mirkill(_x2);
    mirkill(ta);
    mirkill(da);
    mirkill(p);
    mirkill(a);
    mirkill(b);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    epoint_free(g);
    epoint_free(w);
    mirexit();

    return ret;
}


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
)
{
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

    struct FPECC *cfig = &Ecc256;
    big k, x1, y1, x2, y2, _x1, _x2, da, ta;
    big a, b, p, n, x, y;
    epoint *g, *w;
    int ret = 0;
    unsigned char kx1buf[32], ky1buf[32];
    unsigned char kx2buf[32], ky2buf[32];
    unsigned char xubuf[32];
    unsigned char yubuf[32];
    unsigned char buf[256];

    unsigned char za[32];
    unsigned char zb[32];
    unsigned char hash[32];




    miracl *mip = mirsys(20, 0);

    mip->IOBASE = 16;
    k  = mirvar(0);
    x1 = mirvar(0);
    y1 = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    _x1 = mirvar(0);
    _x2 = mirvar(0);
    ta = mirvar(0);
    da = mirvar(0);

    p = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);


    cinstr(p, cfig->p);
    cinstr(a, cfig->a);
    cinstr(b, cfig->b);
    cinstr(n, cfig->n);
    cinstr(x, cfig->x);
    cinstr(y, cfig->y);
    ecurve_init(a, b, p, MR_PROJECTIVE);
    g = epoint_init();
    w = epoint_init();


    sm3_z(ida, idalen, xa, xalen, ya, yalen, za);
    sm3_z(idb, idblen, xb, xblen, yb, yblen, zb);


    bytes_to_big(kxblen, (char *)kxb, x1);
    bytes_to_big(kyblen, (char *)kyb, y1);

    if(!epoint_set(x1, y1, 0, g))
        goto exit_sm2_keyagreement_b;

    big_to_bytes(32, x1, (char *)kx1buf, TRUE);
    big_to_bytes(32, y1, (char *)ky1buf, TRUE);
    memcpy(buf, kx1buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(16, (char *)buf, _x1);
#if SM2_DEBUG
    PrintBig(mip, _x1);
#endif


    bytes_to_big(private_b_len, (char *)private_b, da);

    bytes_to_big(private_b_tmp_len, (char *)private_b_tmp, k);



    mad(_x1, k, da, n, n, ta);
#if SM2_DEBUG
    PrintBig(mip, ta);
#endif



    bytes_to_big(kxalen, (char *)kxa, x2);
    bytes_to_big(kyalen, (char *)kya, y2);
    if(!epoint_set(x2, y2, 0, g))
        goto exit_sm2_keyagreement_b;

    big_to_bytes(32, x2, (char *)kx2buf, TRUE);
    big_to_bytes(32, y2, (char *)ky2buf, TRUE);
    memcpy(buf, kx2buf + 16, 16);
    buf[0] |= 0x80;
    bytes_to_big(16, (char *)buf, _x2);
#if SM2_DEBUG
    PrintBig(mip, _x2);
#endif

    bytes_to_big(xalen, (char *)xa, x);
    bytes_to_big(yalen, (char *)ya, y);
    if(!epoint_set(x, y, 0, w))
        goto exit_sm2_keyagreement_b;

    ecurve_mult(_x2, g, g);
    ecurve_add(w, g);
    ecurve_mult(ta, g, g);
    if(point_at_infinity(g))
        goto exit_sm2_keyagreement_b;


    epoint_get(g, x, y);
    big_to_bytes(32, x, (char *)xubuf, TRUE);
    big_to_bytes(32, y, (char *)yubuf, TRUE);
#if SM2_DEBUG
    printf("xu & yu: ");
    PrintBuf(xubuf, 32);
    PrintBuf(yubuf, 32);
#endif


    memcpy(buf, xubuf, 32);
    memcpy(buf + 32, yubuf, 32);
    memcpy(buf + 64, za, 32);
    memcpy(buf + 96, zb, 32);
    kdf_key(buf, 128, keylen, keybuf);
#if SM2_DEBUG
    printf("buf: ");
    PrintBuf(buf, 128);

    printf("Kb: ");
    PrintBuf(keybuf, keylen);
#endif

    if((s2 != NULL) || (sb != NULL))
    {
        memcpy(buf, xubuf, 32);
        memcpy(buf + 32, za, 32);
        memcpy(buf + 64, zb, 32);
        memcpy(buf + 96, kx2buf, 32);
        memcpy(buf + 128, ky2buf, 32);
        memcpy(buf + 160, kx1buf, 32);
        memcpy(buf + 192, ky1buf, 32);
        sm3(buf, 32 * 7, hash);
    }

    if(s2 != NULL)
    {
        buf[0] = 0x03;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, s2);
    }

    if(sb != NULL)
    {
        buf[0] = 0x02;
        memcpy(buf + 1, yubuf, 32);
        memcpy(buf + 33, hash, 32);
        sm3(buf, 65, sb);
    }

    ret = 1;

exit_sm2_keyagreement_b:

    mirkill(k);
    mirkill(x1);
    mirkill(y1);
    mirkill(x2);
    mirkill(y2);
    mirkill(_x1);
    mirkill(_x2);
    mirkill(ta);
    mirkill(da);
    mirkill(p);
    mirkill(a);
    mirkill(b);
    mirkill(n);
    mirkill(x);
    mirkill(y);
    epoint_free(g);
    epoint_free(w);
    mirexit();

    return ret;
}


#endif
