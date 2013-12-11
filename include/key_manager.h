#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "mx_std.h"

#define PWD_MAX_LENGTH 8
#define ACCESS_ALLOW 1
#define ACCESS_DENY 0
//every index has four key
//#define TYPE_SIGN_PUB 0
//#define TYPE_SIGN_PRI 1
//#define TYPE_ENC_PUB 2
//#define TYPE_ENC_PRI 3
//every key kas six type
#define TYPE_RSA_PUB 0
#define TYPE_RSA_PRI 1
#define TYPE_ECC_PUB 2
#define TYPE_ECC_PRI 3
#define TYPE_ECC_CIPH 4
#define TYPE_ECC_SIGN 5

#define MAX_KEY_SIZE 256 
#define KEK_SIZE 128
#define MAX_COLUMN 4

#define SPI_KEY_START 0x00000000
#define SPI_KEY_END 0x00600000

typedef struct header_st {
    uint32_t total_size;
    uint32_t count;
    uint32_t reserved;
} KEYHEADER;

typedef struct kek_st{
    uint32_t index;
    uint8_t data[KEK_SIZE];
} KEKINFO;
typedef struct key_st{
    uint32_t type;
    uint32_t index;
    uint32_t access;
    union key_data {
        RSArefPublicKey rsa_puk;
        RSArefPrivateKey rsa_prk;
        ECCrefPublicKey ecc_puk;
        ECCrefPrivateKey ecc_prk;
        ECCCipher ecc_cipher;
        ECCSignature ecc_sign;
        KEKINFO kek;
    } data; 
} KEYINFO;

KEYHEADER key_header;
KEYINFO keys[MAX_KEY_SIZE];

int get_key(uint32_t type, uint32_t index, KEYINFO *keyinfo);
/*int set_private_key_access(uint32_t index, uint32_t allow);*/
int load_all_keys(KEYHEADER key_header, KEYINFO keys[MAX_KEY_SIZE]);
int save_all_keys(KEYHEADER key_header, KEYINFO keys[MAX_KEY_SIZE]);
int process_command_key(uint8_t *params, uint8_t *result);
#endif
