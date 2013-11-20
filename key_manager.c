#include "key_manager.h"
#include <stdio.h>
#include <string.h>


#define PWD_MAX_LENGTH 8
#define ACCESS_ALLOW 1
#define ACCESS_DENY 0
#define TYPE_RSA_PUB 0
#define TYPE_RSA_PRI 0
#define TYPE_ECC_PUB 0
#define TYPE_ECC_PRI 0
#define TYPE_RSA_PUB 0
#define TYPE_RSA_PUB 0

u_int32_t set_private_key_access(u_int32_t index, u_int32_t allow)
{
    do{
        keys[index].access = allow; 
    }
    while(keys[index].next != NULL);
    return 0; 
}


u_int32_t check_passwd(const unsigned char *pwd, u_int32_t pwd_len)
{
    if(pwd_len != 8) return 0;
    char pwd_inner[9] = "12345678";
    return strncmp(pwd,pwd_inner,PWD_MAX_LENGTH);
}
u_int32_t get_private_key_access_right (
  u_int32_t index,
  unsigned char *pwd,
  u_int32_t pwd_len)
{
    if(!check_passwd(pwd,pwd_len)) {
        set_private_key_access(index, ACCESS_ALLOW); 
    }
}

u_int32_t release_private_key_access (
  u_int32_t index)
{
    set_private_key_access(index, ACCESS_DENY);
}

u_int32_t SDF_ExportSignPublicKey_RSA(
  u_int32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey)
{
    *pucPublicKey = get_key(uiKeyIndex,)
}

u_int32_t SDF_ExportEncPublicKey_RSA(
  void *hSessionHandle,
  u_int32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey);

u_int32_t SDF_ExportSignPublicKey_ECC(
  void *hSessionHandle,
  u_int32_t uiKeyIndex,
  ECCrefPublicKey *pucPublicKey);

u_int32_t SDF_ExportEncPublicKey_ECC(
  void *hSessionHandle,
  u_int32_t uiKeyIndex,
  ECCrefPublicKey *pucPublicKey);

u_int32_t SDF_ImportKeyWithISK_RSA (
  void *hSessionHandle,
  u_int32_t uiISKIndex,
  unsigned char *pucKey,
  u_int32_t *puiKeyLength,
  void **phKeyHandle);

u_int32_t SDF_ImportKeyWithISK_ECC (
  void *hSessionHandle,
  u_int32_t uiISKIndex,
  ECCCipher *pucKey,
  void **phKeyHandle);

u_int32_t SDF_ImportKeyWithKEK (
  void *hSessionHandle,
  u_int32_t uiAlgID,
  u_int32_t uiKEKIndex,
  unsigned char *pucKey,
  u_int32_t *puiKeyLength,
  void **phKeyHandle);

u_int32_t SDF_ImportKey (
  void *hSessionHandle,
  unsigned char *pucKey,
  u_int32_t uiKeyLength,
  void **phKeyHandle);

u_int32_t SDF_DestoryKey (
  void *hSessionHandle,
  void *hKeyHandle);

u_int32_t SDF_ExchangeDigitEnvelopeBaseOnRSA(
  void *hSessionHandle,
  u_int32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey,
  unsigned char *pucDEInput,
  u_int32_t uiDELength,
  unsigned char *pucDEOutput,
  u_int32_t *puiDELength);

u_int32_t SDF_ExchangeDigitEnvelopeBaseOnECC(
  void *hSessionHandle,
  u_int32_t uiKeyIndex,
  u_int32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  ECCCipher *pucEncDataIn,
  ECCCipher *pucEncDataOut);

u_int32_t SDF_GenerateKeyPair_RSA(
  void *hSessionHandle,
  u_int32_t uiKeyBits,
  RSArefPublicKey *pucPublicKey,
  RSArefPrivateKey *pucPrivateKey);

u_int32_t SDF_GenerateKeyWithIPK_RSA (
  void *hSessionHandle,
  u_int32_t uiIPKIndex,
  u_int32_t uiKeyBits,
  unsigned char *pucKey,
  u_int32_t *puiKeyLength, 
  void **phKeyHandle);

u_int32_t SDF_GenerateKeyWithEPK_RSA (
  void *hSessionHandle,
  u_int32_t uiKeyBits,
  RSArefPublicKey *pucPublicKey,
  unsigned char *pucKey,
  u_int32_t *puiKeyLength,
  void **phKeyHandle);

u_int32_t SDF_GenerateKeyPair_ECC(
  void *hSessionHandle,
  u_int32_t uiAlgID,
  u_int32_t uiKeyBits,
  ECCrefPublicKey *pucPublicKey,
  ECCrefPrivateKey *pucPrivateKey);

u_int32_t SDF_GenerateKeyWithIPK_ECC (
  void *hSessionHandle,
  u_int32_t uiIPKIndex,
  u_int32_t uiKeyBits,
  ECCCipher *pucKey,
  void **phKeyHandle);

u_int32_t SDF_GenerateKeyWithEPK_ECC (
  void *hSessionHandle,
  u_int32_t uiKeyBits,
  u_int32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  ECCCipher *pucKey,
  void **phKeyHandle);

u_int32_t SDF_GenerateAgreementDataWithECC (
  void *hSessionHandle,
  u_int32_t uiISKIndex,
  u_int32_t uiKeyBits,
  unsigned char *pucSponsorID,
  u_int32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  void **phAgreementHandle);

u_int32_t SDF_GenerateKeyWithECC (
  void *hSessionHandle,
  unsigned char *pucResponseID,
  u_int32_t uiResponseIDLength,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void *hAgreementHandle,
  void **phKeyHandle);

u_int32_t SDF_GenerateAgreementDataAndKeyWithECC (
  void *hSessionHandle,
  u_int32_t uiISKIndex,
  u_int32_t uiKeyBits,
  unsigned char *pucResponseID,
  u_int32_t uiResponseIDLength,
  unsigned char *pucSponsorID,
  u_int32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void **phKeyHandle);

u_int32_t SDF_GenerateKeyWithKEK (
  void *hSessionHandle,
  u_int32_t uiKeyBits,
  u_int32_t uiAlgID,
  u_int32_t uiKEKIndex,
  unsigned char *pucKey,
  u_int32_t *puiKeyLength,
  void **phKeyHandle);

u_int32_t main(u_int32_t argc, const char *argv[])
{
    printf("key_info size(%ld)",sizeof(key_info));
    printf("check result=%d\n",check_passwd(argv[1], 8));
    return 0;
}


