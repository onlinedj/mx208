#include "key_manager.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdlib.h>

#include "mxpci_spi.h"
#include "commands.h"
#include "queue.h"

static uint8_t *buffer;
int alloc_buffer(KEYHEADER key_header, KEYINFO keys[MAX_KEY_SIZE])
{
    buffer = malloc(key_header.total_size);
    int i = 0;
    for(i = 0; i < key_header.count;i++)
    {
         
    }
}

int load_all_keys(KEYHEADER key_header, KEYINFO keys[MAX_KEY_SIZE])
{

}
int save_all_keys(KEYHEADER key_header, KEYINFO keys[MAX_KEY_SIZE])
{
    alloc_buffer(keys);
    int fd;
    fd = open("/dev/mxpcispi", O_WRONLY);

    if(fd > 0)
    {
        printf("open successfully\n");
        FlashUserInfo userinfo;
        userinfo.addr = SPI_KEY_START;
        userinfo.len = sizeof(KEYINFO)*MAX_KEY_SIZE;
        userinfo.buf = &keys;
        int error = ioctl(fd, IOCTL_PCI_FLASH_WRITE, &userinfo);
        userinfo.addr = 
        printf("close file errorno=%d\n",error);
        close(fd);
        return 0;
    }
    else
    {
        printf("open failed:%s\n", strerror(errno));
        return (-1);
    }

}

int process_command_key(uint8_t *params, uint8_t *output)
{
    int result = 0;
    HEADER header;
    get_header(&header,&params);
    switch(header.func_id)
    {
    case GET_KEY_ACCESS:
        break;
    case RELEASE_KEY_ACCESS:
        break;
    case EXPORT_SIGN_PUB_KEY_RSA:
        break;
    case EXPORT_ENC_PUB_KEY_RSA:
        break;
    case EXPORT_SIGN_PUB_KEY_ECC:
        break;
    case EXPORT_ENC_PUB_KEY_ECC:
        break;
    case GENERATE_KEYPAIR_RSA:
        break;
    case GENERATE_KEY_IPK_RSA:
        break;
    case GENERATE_KEY_EPK_RSA:
        break;
    case GENERATE_KEYPAIR_ECC:
        break;
    case GENERATE_KEY_IPK_ECC:
        break;
    case GENERATE_KEY_EPK_ECC:
        break;
    case GENERATE_KEY_KEK:
        break;
    case GENERATE_KEY_ECC:
        break;
    case GENERATE_AGREEMENT_DATA_ECC:
        break;
    case GENERATE_AGREEMENT_DATA_KEY_ECC:
        break;
    case IMPORT_KEY_ISK_RSA:
        break;
    case IMPORT_KEY_ISK_ECC:
        break;
    case IMPORT_KEY_KEK:
        break;
    case IMPORT_KEY:
        break;
    case DESTROY_KEY:
        break;
    case EXCHANGE_DIGIT_ENVELOPE_RSA:
        break;
    case EXCHANGE_DIGIT_ENVELOPE_ECC:
        break;
    
    default:
        printf("no command found in key_manager_process\n");
        break;
    }
    return result;
}

int get_key(uint32_t type, uint32_t index, KEYINFO *info)
{
    //TODO
    return 0;
}

int set_private_key_access(uint32_t index, uint32_t allow)
{
    /*do{
        keys[index].access = allow; 
    }
    while(keys[index].next != NULL);*/
    //TODO
    return 0; 
}

int check_passwd(const uint8_t *pwd, uint32_t pwd_len)
{
    if(pwd_len != 8) return 0;
    char pwd_inner[9] = "12345678";
    return strncmp((char *)pwd,pwd_inner,PWD_MAX_LENGTH);
}
int get_private_key_access_right (
  uint32_t index,
  uint8_t *pwd,
  uint32_t pwd_len)
{
    int result = -1;
    if(!check_passwd(pwd,pwd_len)) {
        result = set_private_key_access(index, ACCESS_ALLOW); 
    }
    return result;
}

int release_private_key_access (
  uint32_t index)
{
    int result = -1;
    result = set_private_key_access(index, ACCESS_ALLOW); 
    return result;
}

int export_sign_public_key_rsa(
  uint32_t index,
  RSArefPublicKey *key)
{
     KEYINFO info;
     int result = get_key(TYPE_SIGN_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.rsa_puk,sizeof(*key));
     }
     return result;
}

int export_enc_public_key_rsa(
  uint32_t index,
  RSArefPublicKey *key)
{
     KEYINFO info;
     int result = get_key(TYPE_ENC_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.rsa_puk,sizeof(*key));
     }
     return result;
    
}

uint32_t export_sign_public_key_ecc(
  uint32_t index,
  ECCrefPublicKey *key)
{
     KEYINFO info;
     int result = get_key(TYPE_SIGN_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.ecc_puk,sizeof(*key));
     }
     return result;
    
}

uint32_t export_enc_public_key_ecc(
  void *hSessionHandle,
  uint32_t index,
  ECCrefPublicKey *key);

uint32_t SDF_ImportKeyWithISK_RSA (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  uint8_t *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ImportKeyWithISK_ECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  ECCCipher *pucKey,
  void **phKeyHandle);

uint32_t SDF_ImportKeyWithKEK (
  void *hSessionHandle,
  uint32_t uiAlgID,
  uint32_t uiKEKIndex,
  uint8_t *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ImportKey (
  void *hSessionHandle,
  uint8_t *pucKey,
  uint32_t uiKeyLength,
  void **phKeyHandle);

uint32_t SDF_DestoryKey (
  void *hSessionHandle,
  void *hKeyHandle);

uint32_t SDF_ExchangeDigitEnvelopeBaseOnRSA(
  void *hSessionHandle,
  uint32_t index,
  RSArefPublicKey *key,
  uint8_t *pucDEInput,
  uint32_t uiDELength,
  uint8_t *pucDEOutput,
  uint32_t *puiDELength);

uint32_t SDF_ExchangeDigitEnvelopeBaseOnECC(
  void *hSessionHandle,
  uint32_t index,
  uint32_t uiAlgID,
  ECCrefPublicKey *key,
  ECCCipher *pucEncDataIn,
  ECCCipher *pucEncDataOut);

uint32_t SDF_GenerateKeyPair_RSA(
  void *hSessionHandle,
  uint32_t uiKeyBits,
  RSArefPublicKey *key,
  RSArefPrivateKey *pucPrivateKey);

uint32_t SDF_GenerateKeyWithIPK_RSA (
  void *hSessionHandle,
  uint32_t uiIPKIndex,
  uint32_t uiKeyBits,
  uint8_t *pucKey,
  uint32_t *puiKeyLength, 
  void **phKeyHandle);

uint32_t SDF_GenerateKeyWithEPK_RSA (
  void *hSessionHandle,
  uint32_t uiKeyBits,
  RSArefPublicKey *key,
  uint8_t *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_GenerateKeyPair_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  uint32_t uiKeyBits,
  ECCrefPublicKey *key,
  ECCrefPrivateKey *pucPrivateKey);

uint32_t SDF_GenerateKeyWithIPK_ECC (
  void *hSessionHandle,
  uint32_t uiIPKIndex,
  uint32_t uiKeyBits,
  ECCCipher *pucKey,
  void **phKeyHandle);

uint32_t SDF_GenerateKeyWithEPK_ECC (
  void *hSessionHandle,
  uint32_t uiKeyBits,
  uint32_t uiAlgID,
  ECCrefPublicKey *key,
  ECCCipher *pucKey,
  void **phKeyHandle);

uint32_t SDF_GenerateAgreementDataWithECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  uint32_t uiKeyBits,
  uint8_t *pucSponsorID,
  uint32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  void **phAgreementHandle);

uint32_t SDF_GenerateKeyWithECC (
  void *hSessionHandle,
  uint8_t *pucResponseID,
  uint32_t uiResponseIDLength,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void *hAgreementHandle,
  void **phKeyHandle);

uint32_t SDF_GenerateAgreementDataAndKeyWithECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  uint32_t uiKeyBits,
  uint8_t *pucResponseID,
  uint32_t uiResponseIDLength,
  uint8_t *pucSponsorID,
  uint32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void **phKeyHandle);

uint32_t SDF_GenerateKeyWithKEK (
  void *hSessionHandle,
  uint32_t uiKeyBits,
  uint32_t uiAlgID,
  uint32_t uiKEKIndex,
  uint8_t *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

int main(int argc, const char *argv[])
{
    printf("key_info size(%ld)\n",sizeof(KEYINFO));
    printf("rsa pub size(%ld)\n",sizeof(RSArefPublicKey));
    printf("rsa pri size(%ld)\n",sizeof(RSArefPrivateKey));
    printf("ecc pub size(%ld)\n",sizeof(ECCrefPublicKey));
    printf("ecc pri size(%ld)\n",sizeof(ECCrefPrivateKey));
    printf("ecc cipher size(%ld)\n",sizeof(ECCCipher));
    printf("ecc sign size(%ld)\n",sizeof(ECCSignature));
//    printf("check result=%d\n",check_passwd(argv[1], 8));
    return 0;
}


