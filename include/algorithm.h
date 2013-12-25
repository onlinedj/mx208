#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "sm2.h"
#include "sm4.h"
#include "miracl.h"
#include "mxpci_dev.h"
#include "key_manager.h"
/*
#define ECCref_MAX_BITS			256 
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
*/

#define GET_ARRAY_LEN(array,len){len = (sizeof(array) / sizeof(array[0]));}

#define SDF_GenerateRandom       0x00000006
#define SDF_GenerateKeyPair_ECC          0x01000010
#define SDF_GenerateKeyWithIPK_ECC		 0x01000011
#define SDF_GenerateKeyWithEPK_ECC       0x01000012
#define SDF_ImportKeyWithISK_ECC       0x01000013
#define SDF_ExchangeDigitEnvelopeBaseOnECC       0x01000017
#define SDF_GenerateKeyWithKEK      0x01000018
#define SDF_ImportKeyWithKEK     0x01000019
#define SDF_ExternalSign_ECC     0x02000005
#define SDF_ExternalVerify_ECC   0x02000006
#define SDF_InternalSign_ECC     0x02000007
#define SDF_InternalVerify_ECC   0x02000008
#define SDF_ExternalEncrytp_ECC  0x02000009
#define SDF_ExternalDecrypt_ECC  0x02000010
#define SDF_Encrypt              0x02000011
#define SDF_Decrypt              0x02000012
#define SDF_CalculateMAC         0x02000013

#define SGD_SM1_ECB 0x00000101
#define SGD_SM1_CBC 0x00000102
#define SGD_SM1_CFB 0x00000104 
#define SGD_SM1_OFB 0x00000108
#define SGD_SM4_ECB 0x00000401
#define SGD_SM4_CBC 0x00000402
#define SGD_SM4_CFB 0x00000404 
#define SGD_SM4_OFB 0x00000408

/*
typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;
    unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;


typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];	
	unsigned char s[ECCref_MAX_LEN];	
} ECCSignature;

typedef struct ECCCipher_st
{
unsigned char x[ECCref_MAX_LEN]; 
unsigned char y[ECCref_MAX_LEN]; 
unsigned char C[1024];
unsigned char M[ECCref_MAX_LEN];
} ECCCipher;
*/

/*
get GenerateRandom&sessionKey
uiLength : length of nums
pucRandom : random nums
*/
int ALG_SDF_GenerateRandom(unsigned int uiLength,unsigned char *pucRandom);

/*
get ECC keypair 
uiAlgID : flag
uiKeyBits : lenght of keys
pucPublicKey : output pubkey
pucPrivateKey : output privkey
*/
int ALG_SDF_GenerateKeyPair_ECC(unsigned char *wx,unsigned char *wy,unsigned char *privkey);

/*
getsessionkey and encrpyt it
pucPublicKey : eccpubkey
uiKeyBits : key lenth
pucKey : output data
*/
int ALG_SDF_GenerateKeyWith_ECC(ECCrefPublicKey pucPublicKey,unsigned int uiKeyBits,unsigned char *outdata,unsigned int pubkeyLength);

/*
decrpyt session key
uiISKIndex : get privkey
pucKey : output data
*/
int ALG_SDF_ImportKeyWithISK_ECC(ECCrefPrivateKey pucPrivateKey,unsigned char *indata,unsigned int datalength,unsigned int privkeylength,unsigned char *outmsg);

/*
pucPrivateKey : privkey
pucPublicKey : pubkey
pucDataInput : input data
uiInputLength : data length
pucSignature : output data
*/
int ALG_SDF_Sign_ECC(ECCrefPrivateKey pucPrivateKey,ECCrefPublicKey pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *wr, unsigned char *ws,unsigned char* outdata);


int ALG_DirectSign_Ecc(ECCrefPrivateKey pucPrivateKey,unsigned char *pucDataInput,unsigned char *wr, unsigned char *ws,int rdatalen,int sdatalen);
/*
pucPublicKey : pubkey
pucSignature : input signkey
pucDataInput : input signed data
uiInputLength : input signed data length
*/
int ALG_SDF_Verify_ECC(ECCrefPublicKey pucPublicKey,ECCSignature pucSignature,unsigned char *pucDataInput,unsigned int uiInputLength);

/*
ECC encrpty
*/
int ALG_SDF_Encrytp_ECC(unsigned char *inputdata,ECCrefPublicKey pucPublicKey,unsigned int pubkeyLength,unsigned int uiDataLength,unsigned char *outdata);

/*
encrpty
*/
void ALG_SDF_Encrypt(unsigned char *key,int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData);

/*
decrpty
*/
void ALG_SDF_Decrypt(unsigned char *key,int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData);

/*
hmac
*/
void ALG_SDF_CalculateMAC(unsigned char *key,int keylength,unsigned char *text, int textlen, unsigned char *hmac);

/*
hash
*/
void ALG_SDF_HashInit(SM3_CTX *ctx);

void ALG_SDF_HashUpdate(SM3_CTX *ctx, const void *data, int len);

void ALG_SDF_HashFinalSM3_Final(unsigned char *md, SM3_CTX *ctx);

/*
main enter
*/
int process_command_algorithm(unsigned char *params,unsigned char *result);
