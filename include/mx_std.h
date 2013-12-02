/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: mx_std.h
*         Desc: standard API
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-19 15:55:10
*      History:
*
********************************************************************************/
#ifndef MX_STD_H
#define MX_STD_H
#include <stdint.h>
//symmetric cryptographic types
#define SGD_SM1_ECB 0x00000101 
#define SGD_SM1_CBC 0x00000102 
#define SGD_SM1_CFB 0x00000104 
#define SGD_SM1_OFB 0x00000108 
#define SGD_SM1_MAC 0x00000110 
#define SGD_SSF33_ECB 0x00000201 
#define SGD_SSF33_CBC 0x00000202 
#define SGD_SSF33_CFB 0x00000204 
#define SGD_SSF33_OFB 0x00000208 
#define SGD_SSF33_MAC 0x00000210 

//asymmetric cryptographic types
#define SGD_RSA 0x00010000 
#define SGD_SM2_1 0x00020100 
#define SGD_SM2_2 0x00020200 
#define SGD_SM2_3 0x00020400 

//cryptographic hash types
#define SGD_SM3 0x00000001 
#define SGD_SHA1 0x00000002 
#define SGD_SHA256 0x00000004 

//rsa max values
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7)/ 8)

//ecc max values
#define ECCref_MAX_BITS 256
#define ECCref_MAX_LEN ((ECCref_MAX_BITS+7) / 8)

//error code
#define SDR_OK 0x0 
#define SDR_BASE 0x01000000 //错误码基础值
#define SDR_UNKNOWERR SDR_BASE + 0x00000001 //未知错误
#define SDR_NOTSUPPORT SDR_BASE + 0x00000002 //不支持的接口调用
#define SDR_COMMFAIL SDR_BASE + 0x00000003 //与设备通信失败
#define SDR_HARDFAIL SDR_BASE + 0x00000004 //运算模块无响应
#define SDR_OPENDEVICE SDR_BASE + 0x00000005 //打开设备失败
#define SDR_OPENSESSION SDR_BASE + 0x00000006 //创建会话失败
#define SDR_PARDENY SDR_BASE + 0x00000007 //无私钥使用权限
#define SDR_KEYNOTEXIST SDR_BASE + 0x00000008 //不存在的密钥调用
#define SDR_ALGNOTSUPPORT SDR_BASE + 0x00000009 //不支持的算法调用
#define SDR_ALGMODNOTSUPPORT SDR_BASE + 0x0000000A //不支持的算法模式调用
#define SDR_PKOPERR SDR_BASE + 0x0000000B //公钥运算失败
#define SDR_SKOPERR SDR_BASE + 0x0000000C //私钥运算失败
#define SDR_SIGNERR SDR_BASE + 0x0000000D //签名运算失败
#define SDR_VERIFYERR SDR_BASE + 0x0000000E //验证签名失败
#define SDR_SYMOPERR SDR_BASE + 0x0000000F //对称算法运算失败
#define SDR_STEPERR SDR_BASE + 0x00000010 //多步运算步骤错误
#define SDR_FILESIZEERR SDR_BASE + 0x00000011 //文件长度超出限制
#define SDR_FILENOEXIST SDR_BASE + 0x00000012 //指定的文件不存在
#define SDR_FILEOFSERR SDR_BASE + 0x00000013 //文件起始位置错误
#define SDR_KEYTYPEERR SDR_BASE + 0x00000014 //密钥类型错误
#define SDR_KEYERR SDR_BASE + 0x00000015 //密钥错误

//encryption device information
typedef struct DeviceInfo_st{
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    uint32_t DeviceVersion;
    uint32_t StandardVersion;
    uint32_t AsymAlgAbility[2];
    uint32_t SymAlgAbility;
    uint32_t HashAlgAbility;
    uint32_t BufferSize;
} DEVICEINFO;

//TODO device key store
//TODO user keypair store
//TODO session key store
//TODO key encrypt key store


//rsa public key
typedef struct RSArefPublicKey_st
{
    uint32_t bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

//rsa private key
typedef struct RSArefPrivateKey_st
{
    uint32_t bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

//ecc public key
typedef struct ECCrefPublicKey_st
{
    uint32_t bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;
//ecc private key
typedef struct ECCrefPrivateKey_st
{
    uint32_t bits;
    unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

//ecc cipher
typedef struct ECCCipher_st
{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char C[ECCref_MAX_LEN];
    unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

//ecc sign
typedef struct ECCSignature_st
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;




//device management functions
uint32_t SDF_OpenDevice(void **phDeviceHandle);

uint32_t SDF_CloseDevice(void *hDeviceHandle);

uint32_t SDF_OpenSession(
  void *hDeviceHandle,
  void **phSessionHandle);

uint32_t SDF_CloseSession(void *hSessionHandle);

uint32_t SDF_GetDeviceInfo (
  void *hSessionHandle,
  DEVICEINFO *pstDeviceInfo);

uint32_t SDF_GenerateRandom (
  void *hSessionHandle,
  uint32_t uiLength,
  unsigned char *pucRandom);

uint32_t SDF_GetPrivateKeyAccessRight (
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  unsigned char *pucPassword,
  uint32_t uiPwdLength);

uint32_t SDF_ReleasePrivateKeyAccessRight (
  void *hSessionHandle,
  uint32_t uiKeyIndex);

uint32_t SDF_ExportSignPublicKey_RSA(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey);

uint32_t SDF_ExportEncPublicKey_RSA(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey);

uint32_t SDF_GenerateKeyPair_RSA(
  void *hSessionHandle,
  uint32_t uiKeyBits,
  RSArefPublicKey *pucPublicKey,
  RSArefPrivateKey *pucPrivateKey);

uint32_t SDF_GenerateKeyWithIPK_RSA (
  void *hSessionHandle,
  uint32_t uiIPKIndex,
  uint32_t uiKeyBits,
  unsigned char *pucKey,
  uint32_t *puiKeyLength, 
  void **phKeyHandle);

uint32_t SDF_GenerateKeyWithEPK_RSA (
  void *hSessionHandle,
  uint32_t uiKeyBits,
  RSArefPublicKey *pucPublicKey,
  unsigned char *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ImportKeyWithISK_RSA (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  unsigned char *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ExchangeDigitEnvelopeBaseOnRSA(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  RSArefPublicKey *pucPublicKey,
  unsigned char *pucDEInput,
  uint32_t uiDELength,
  unsigned char *pucDEOutput,
  uint32_t *puiDELength);

uint32_t SDF_ExportSignPublicKey_ECC(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  ECCrefPublicKey *pucPublicKey);

uint32_t SDF_ExportEncPublicKey_ECC(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  ECCrefPublicKey *pucPublicKey);

uint32_t SDF_GenerateKeyPair_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  uint32_t uiKeyBits,
  ECCrefPublicKey *pucPublicKey,
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
  ECCrefPublicKey *pucPublicKey,
  ECCCipher *pucKey,
  void **phKeyHandle);

uint32_t SDF_ImportKeyWithISK_ECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  ECCCipher *pucKey,
  void **phKeyHandle);

uint32_t SDF_GenerateAgreementDataWithECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  uint32_t uiKeyBits,
  unsigned char *pucSponsorID,
  uint32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  void **phAgreementHandle);

uint32_t SDF_GenerateKeyWithECC (
  void *hSessionHandle,
  unsigned char *pucResponseID,
  uint32_t uiResponseIDLength,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void *hAgreementHandle,
  void **phKeyHandle);

uint32_t SDF_GenerateAgreementDataAndKeyWithECC (
  void *hSessionHandle,
  uint32_t uiISKIndex,
  uint32_t uiKeyBits,
  unsigned char *pucResponseID,
  uint32_t uiResponseIDLength,
  unsigned char *pucSponsorID,
  uint32_t uiSponsorIDLength,
  ECCrefPublicKey *pucSponsorPublicKey,
  ECCrefPublicKey *pucSponsorTmpPublicKey,
  ECCrefPublicKey *pucResponsePublicKey,
  ECCrefPublicKey *pucResponseTmpPublicKey,
  void **phKeyHandle);

uint32_t SDF_ExchangeDigitEnvelopeBaseOnECC(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  uint32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  ECCCipher *pucEncDataIn,
  ECCCipher *pucEncDataOut);

uint32_t SDF_GenerateKeyWithKEK (
  void *hSessionHandle,
  uint32_t uiKeyBits,
  uint32_t uiAlgID,
  uint32_t uiKEKIndex,
  unsigned char *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ImportKeyWithKEK (
  void *hSessionHandle,
  uint32_t uiAlgID,
  uint32_t uiKEKIndex,
  unsigned char *pucKey,
  uint32_t *puiKeyLength,
  void **phKeyHandle);

uint32_t SDF_ImportKey (
  void *hSessionHandle,
  unsigned char *pucKey,
  uint32_t uiKeyLength,
  void **phKeyHandle);

uint32_t SDF_DestoryKey (
  void *hSessionHandle,
  void *hKeyHandle);

//asym functions
uint32_t SDF_ExternalPublicKeyOperation_RSA(
  void *hSessionHandle,
  RSArefPublicKey *pucPublicKey,
  unsigned char *pucDataInput,
  uint32_t uiInputLength,
  unsigned char *pucDataOutput,
  uint32_t *puiOutputLength);

uint32_t SDF_ExternalPrivateKeyOperation_RSA(
  void *hSessionHandle,
  RSArefPrivateKey *pucPrivateKey,
  unsigned char *pucDataInput,
  uint32_t uiInputLength,
  unsigned char *pucDataOutput,
  uint32_t *puiOutputLength);

uint32_t SDF_InternalPublicKeyOperation_RSA(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  unsigned char *pucDataInput,
  uint32_t uiInputLength,
  unsigned char *pucDataOutput,
  uint32_t *puiOutputLength);

uint32_t SDF_InternalPrivateKeyOperation_RSA(
  void *hSessionHandle,
  uint32_t uiKeyIndex,
  unsigned char *pucDataInput,
  uint32_t uiInputLength,
  unsigned char *pucDataOutput,
  uint32_t *puiOutputLength);

uint32_t SDF_ExternalSign_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  ECCrefPrivateKey *pucPrivateKey,
  unsigned char *pucData,
  uint32_t uiDataLength,
  ECCSignature *pucSignature);

uint32_t SDF_ExternalVerify_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  unsigned char *pucDataInput,
  uint32_t uiInputLength,
  ECCSignature *pucSignature);

uint32_t SDF_InternalSign_ECC(
  void *hSessionHandle,
  uint32_t uiISKIndex,
  unsigned char *pucData,
  uint32_t uiDataLength,
  ECCSignature *pucSignature);

uint32_t SDF_InternalVerify_ECC(
  void *hSessionHandle,
  uint32_t uiISKIndex,
  unsigned char *pucData,
  uint32_t uiDataLength,
  ECCSignature *pucSignature);

uint32_t SDF_ExternalEncrytp_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  unsigned char *pucData,
  uint32_t uiDataLength,
  ECCCipher *pucEncData);

uint32_t SDF_ExternalDecrypt_ECC(
  void *hSessionHandle,
  uint32_t uiAlgID,
  ECCrefPrivateKey *pucPrivateKey,
  ECCCipher *pucEncData,
  unsigned char *pucData,
  uint32_t *puiDataLength);

//sym functions
uint32_t SDF_Encrypt(
  void *hSessionHandle,
  void *hKeyHandle,
  uint32_t uiAlgID,
  unsigned char *pucIV,
  unsigned char *pucData,
  uint32_t uiDataLength,
  unsigned char *pucEncData,
  uint32_t *puiEncDataLength);

uint32_t SDF_Decrypt (
  void *hSessionHandle,
  void *hKeyHandle,
  uint32_t uiAlgID,
  unsigned char *pucIV,
  unsigned char *pucEncData,
  uint32_t uiEncDataLength,
  unsigned char *pucData,
  uint32_t *puiDataLength);

uint32_t SDF_CalculateMAC(
  void *hSessionHandle,
  void *hKeyHandle,
  uint32_t uiAlgID,
  unsigned char *pucIV,
  unsigned char *pucData,
  uint32_t uiDataLength,
  unsigned char *pucMAC,
  uint32_t *puiMACLength);

//hash functions
uint32_t SDF_HashInit(
  void *hSessionHandle,
  uint32_t uiAlgID,
  ECCrefPublicKey *pucPublicKey,
  unsigned char *pucID,
  uint32_t uiIDLength);

uint32_t SDF_HashUpdate(
  void *hSessionHandle,
  unsigned char *pucData,
  uint32_t uiDataLength);

uint32_t SDF_HashFinal(
  void *hSessionHandle,
  unsigned char *pucHash,
  uint32_t *puiHashLength);

//file modify
uint32_t SDF_CreateFile(
  void *hSessionHandle,
  unsigned char *pucFileName,
  uint32_t uiNameLen,
  uint32_t uiFileSize);
uint32_t SDF_ReadFile(
  void *hSessionHandle,
  unsigned char *pucFileName,
  uint32_t uiNameLen,
  uint32_t uiOffset,
  uint32_t *puiFileLength,
  unsigned char *pucBuffer);
uint32_t SDF_WriteFile(
  void *hSessionHandle,
  unsigned char *pucFileName,
  uint32_t uiNameLen,
  uint32_t uiOffset,
  uint32_t uiFileLength,
  unsigned char *pucBuffer);
uint32_t SDF_DeleteFile(
  void *hSessionHandle,
  unsigned char *pucFileName,
  uint32_t uiNameLen);


#endif
