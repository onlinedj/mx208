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
#include "data_parser.h"

HEADER_INFO header_info;
KEYINFO keys[MAX_KEY_SIZE];
KEKINFO keks[MAX_KEY_SIZE];

int add_kek(uint32_t index, KEKINFO kekinfo)
{
    
    if(index > 0 && index < MAX_KEY_SIZE &&header_info.count+1<MAX_KEY_SIZE)
    {
         int kek_count = header_info.kek_size/sizeof(KEKINFO);
         keks[kek_count].index = index;
         keks[kek_count].data = kekinfo.data;
    }
    update_header(TYPE_KEK,1);
    return 0;
}

int rm_kek(uint32_t index)
{
    int i;
    int kek_count = header_info.kek_size/sizeof(KEKINFO);
    if(index > 0 && index < MAX_KEY_SIZE)
    {
        for(i=0;i<kek_count;i++)
        {
            if(keks[i].index == index) 
            {
                bzero(keks[i]); 
                break;
            }
        }
        for(;i<kek_count;i++)
        {
            if(i+1<kek_count)
            {
                keks[i] = keks[i+1];
            }
            else 
            {
                bzero(kek[i]); 
            }
        }
        update_header(TYPE_KEK,0);
    }
    return 0;
    
}

int get_kek(uint32_t index, KEKINFO *kekinfo)
{
    int i;
    int kek_count = header_info.kek_size/sizeof(KEKINFO);
    if(index > 0 && index < MAX_KEY_SIZE)
    {
        for(i=0;i<kek_count;i++)
        {
            if(keks[i].index == index) 
            {
                *kekinfo = keks[i]; 
            }
        }
    }
    return 0;
}

int add_key(uint32_t type, uint32_t index, KEYINFO keyinfo)
{
    
    if(index > 0 && index < MAX_KEY_SIZE &&header_info.count+1<MAX_KEY_SIZE)
    {
         keys[header_info.count].type = type;
         keys[header_info.count].index = index;
         keys[header_info.count].access = 0;
         keys[header_info.count].data = keyinfo.data;
    }
    update_header(type,1);
    return 0;
}

int rm_key(uint32_t type, uint32_t index)
{
    int i;
    if(index > 0 && index < MAX_KEY_SIZE)
    {
        for(i=0;i<header_info.count;i++)
        {
            if(keys[i].index == index && keys[i].type == type) 
            {
                bzero(keys[i]); 
                break;
            }
        }
        for(;i<header_info.count;i++)
        {
            if(i+1<header_info.count)
            {
                keys[i] = keys[i+1];
            }
            else 
            {
                bzero(key[i]); 
            }
        }
        update_header(type,0);
    }
    return 0;
    
}

int get_key(uint32_t type, uint32_t index, KEYINFO *keyinfo)
{
    int i;
    if(index > 0 && index < MAX_KEY_SIZE)
    {
        for(i=0;i<header_info.count;i++)
        {
            if(keys[i].index == index && keys[i].type == type) 
            {
                *keyinfo = keys[i]; 
            }
        }
    }
    return 0;
}

int update_header(int type, int add)
{
    if(add)
    {
        if(type == TYPE_KEK)
            header_info.kek_size+=sizeof(KEKINFO);
        else
        {
            header_info.key_size+=sizeof(KEYINFO);
            header_info.key_count++; 
        }
    }else{
        if(type == TYPE_KEK)
            header_info.kek_size-=sizeof(KEKINFO);
        else
        {
            header_info.key_count--; 
            header_info.key_size-=sizeof(KEYINFO);
        }
    }
    return 0;
}

int load_all()
{
    int fd;
    fd = open("/dev/mxpcispi", O_RDONLY);

    if(fd > 0)
    {
        printf("open successfully\n");

        FlashUserInfo userinfo;
        userinfo.addr = SPI_KEY_START;
        userinfo.len = sizeof(HEADER_INFO);
        userinfo.buf = header_info;
        int error = ioctl(fd, IOCTL_PCI_FLASH_READ, &userinfo);
        
        printf("read keyheader errorno=%d\n",error);

        userinfo.addr = SPI_KEY_START+sizeof(HEADER_INFO);
        userinfo.len = header_info.key_size;
        userinfo.buf = keys;
        error = ioctl(fd, IOCTL_PCI_FLASH_READ, &userinfo);
        printf("read keys errorno=%d\n",error);

        userinfo.addr = SPI_KEY_START+sizeof(HEADER_INFO)+header_info.key_size;
        userinfo.len = header_info.kek_size;
        userinfo.buf = keks;
        error = ioctl(fd, IOCTL_PCI_FLASH_READ, &userinfo);
        printf("read keks errorno=%d\n",error);

        close(fd);
        return 0;
    }
    else
    {
        printf("open failed:%s\n", strerror(errno));
        return (-1);
    }
    

}
int save_all()
{
    /*alloc_buffer(keys);*/
    int fd;
    fd = open("/dev/mxpcispi", O_WRONLY);

    if(fd > 0)
    {
        printf("open successfully\n");

        FlashUserInfo userinfo;
        userinfo.addr = SPI_KEY_START;
        userinfo.len = sizeof(HEADER_INFO);
        userinfo.buf = &header_info;
        int error = ioctl(fd, IOCTL_PCI_FLASH_WRITE, &userinfo);
        
        printf("write keyheader errorno=%d\n",error);

        userinfo.addr = SPI_KEY_START+sizeof(HEADER_INFO);
        userinfo.len = header_info.key_size;
        userinfo.buf = keys;
        error = ioctl(fd, IOCTL_PCI_FLASH_WRITE, &userinfo);
        printf("write keys errorno=%d\n",error);

        userinfo.addr = SPI_KEY_START+sizeof(HEADER_INFO)+header_info.key_size;
        userinfo.len = header_info.kek_size;
        userinfo.buf = keks;
        error = ioctl(fd, IOCTL_PCI_FLASH_WRITE, &userinfo);
        printf("write keks errorno=%d\n",error);

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
        get_private_key_access();
        break;
    case RELEASE_KEY_ACCESS:
        release_private_key_access();
        break;
    case EXPORT_SIGN_PUB_KEY_RSA:
        //TODO
        break;
    case EXPORT_ENC_PUB_KEY_RSA:
        //TODO
        break;
    case EXPORT_SIGN_PUB_KEY_ECC:
        export_sign_public_key_ecc();
        break;
    case EXPORT_ENC_PUB_KEY_ECC:
        export_enc_public_key_ecc();
        break;
    case IMPORT_SESSION_KEY:
        import_session_key();
        break;
    case DESTROY_SESSION_KEY:
        destroy_session_key();
        break;
    default:
        printf("no command found in key_manager_process\n");
        break;
    }
    return result;
}


int set_private_key_access(uint32_t index, uint32_t allow)
{
    int i;
    for(i=0;i<header_info.key_count;i++)
    {
        if(keys[i].index == index) 
        {
            keys[i].access = allow; 
        }
    }
    return 0; 
}

int check_passwd(const uint8_t *pwd, uint32_t pwd_len)
{
    if(pwd_len != 8) return 0;
    char pwd_inner[9] = "12345678";
    return strncmp((char *)pwd,pwd_inner,PWD_MAX_LENGTH);
}
int get_private_key_access(
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
     /*KEYINFO info;
     int result = get_key(TYPE_RSA_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.rsa_puk,sizeof(*key));
     }
     return result;*/
    return 0;
}

int export_enc_public_key_rsa(
  uint32_t index,
  RSArefPublicKey *key)
{
     /*KEYINFO info;
     int result = get_key(TYPE_RSA_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.rsa_puk,sizeof(*key));
     }
     return result;*/
    return 0;
    
}

int export_sign_public_key_ecc(
  uint32_t index,
  ECCrefPublicKey *key)
{
     KEYINFO info;
     int result = get_key(TYPE_SIGN_PUB<<16|TYPE_ECC_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.ecc_puk,sizeof(*key));
     }
     return result;
    
}

int export_enc_public_key_ecc(
  uint32_t index,
  ECCrefPublicKey *key)
{
     KEYINFO info;
     int result = get_key(TYPE_ENC_PUB<<16|TYPE_ECC_PUB, index, &info);
     if(result>0)
     {
        memcpy(key,&info.data.ecc_puk,sizeof(*key));
     }
     return result;

}

int import_session_key (
  uint8_t *pucKey,
  uint32_t uiKeyLength,
  void **phKeyHandle);

int destory_session_key (
  void *hKeyHandle);


/*uint32_t SDF_ImportKeyWithISK_RSA (
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
  void **phKeyHandle);*/

/*uint32_t SDF_ExchangeDigitEnvelopeBaseOnRSA(
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
}*/


