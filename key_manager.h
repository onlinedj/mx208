#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H
#include "encrypt.h"
#define MAX_KEY_SIZE 256 
typedef struct key_st{
    u_int32_t type;
    u_int32_t index;
    u_int32_t access;
    union key_data {
        RSArefPublicKey rsa_puk;
        RSArefPrivateKey rsa_prk;
        ECCrefPublicKey ecc_puk;
        ECCrefPrivateKey ecc_prk;
        ECCCipher ecc_cipher;
        ECCSignature ecc_sign;
    } data; 
    struct key_st *next;
} key_info;

key_info keys[MAX_KEY_SIZE];

u_int32_t get_key(u_int32_t type, u_int32_t index);
u_int32_t set_private_key_access(u_int32_t index, u_int32_t allow);
u_int32_t load_all_keys(key_info keys[MAX_KEY_SIZE]);
#endif
