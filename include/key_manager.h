#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include "mx_std.h"
//do some test
#define KEY_TEST 1
#define DEBUG 1

#define PWD_MAX_LENGTH 8
#define ACCESS_ALLOW 1
#define ACCESS_DENY 0
//every index has four key
#define TYPE_SIGN_PUB 0
#define TYPE_SIGN_PRI 1
#define TYPE_ENC_PUB 2
#define TYPE_ENC_PRI 3
#define TYPE_KEK 4
//every key has two encrypt type
#define TYPE_RSA_PUB 0
#define TYPE_RSA_PRI 1
#define TYPE_ECC_PUB 2
#define TYPE_ECC_PRI 3
#define TYPE_ECC_CIPH 4
#define TYPE_ECC_SIGN 5

#define COMBO_TYPE(a,b) (a<<16|b)

#define MAX_KEY_SIZE 256 
#define KEK_LENGTH 128
#define MAX_COLUMN 4

#define SPI_KEY_START 0x00000000
#define SPI_KEY_END 0x00600000

typedef struct header_st {
    uint32_t key_size;
    uint32_t key_count;
    uint32_t kek_size;
    uint32_t kek_count;
    uint32_t reserved;
} HEADER_INFO;

typedef struct kek_st{
    uint32_t index;
    uint8_t data[KEK_LENGTH];
} KEKINFO;

typedef union key_data_st {
        RSArefPublicKey rsa_puk;
        RSArefPrivateKey rsa_prk;
        ECCrefPublicKey ecc_puk;
        ECCrefPrivateKey ecc_prk;
} KEYDATA; 

typedef struct key_st{
    uint32_t type;
    uint32_t index;
    uint32_t access;
    KEYDATA data;
} KEYINFO;

#ifdef KEY_TEST
int mock_add_keys();
#endif

int get_key(uint32_t type, uint32_t index, KEYINFO *keyinfo);
int add_key(KEYINFO keyinfo);
int rm_key(uint32_t type, uint32_t index);

int get_kek(uint32_t index, KEKINFO *kekinfo);
int add_kek(KEKINFO kekinfo);
int rm_kek(uint32_t index);

/*int set_private_key_access(uint32_t index, uint32_t allow);*/
int load_all();
int save_all();
int init_key_kek();

int process_command_key(uint8_t *params, uint8_t *result);
#endif
