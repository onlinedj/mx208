/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: commands.h
*         Desc: command ids
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-25 14:57:39
*      History:
*
********************************************************************************/
#ifndef COMMANDS_H
#define COMMANDS_H
#define TYPE_DEVICE 0x00000001
#define TYPE_KEY 0x00000002
#define TYPE_ALGORITHM 0x00000004
#define TYPE_FILE 0x00000008
#define COMMAND(type,id) (type<<24|id)
//device type command
#define GET_DEVICE_INFO COMMAND(TYPE_DEVICE,1)
//key type command
#define GET_KEY_ACCESS  COMMAND(TYPE_KEY,1)
#define RELEASE_KEY_ACCESS  COMMAND(TYPE_KEY,1)
#define EXPORT_SIGN_PUB_KEY_RSA COMMAND(TYPE_KEY,1)
#define EXPORT_ENC_PUB_KEY_RSA  COMMAND(TYPE_KEY,2)
#define EXPORT_SIGN_PUB_KEY_ECC COMMAND(TYPE_KEY,1)
#define EXPORT_ENC_PUB_KEY_ECC  COMMAND(TYPE_KEY,2)
#define GENERATE_KEYPAIR_RSA  COMMAND(TYPE_KEY,1)
#define GENERATE_KEY_IPK_RSA  COMMAND(TYPE_KEY,1)
#define GENERATE_KEY_EPK_RSA  COMMAND(TYPE_KEY,1)
#define GENERATE_KEYPAIR_ECC  COMMAND(TYPE_KEY,1)
#define GENERATE_KEY_IPK_ECC  COMMAND(TYPE_KEY,1)
#define GENERATE_KEY_EPK_ECC  COMMAND(TYPE_KEY,1)
#define SDF_GenerateKeyWithKEK COMMAND(TYPE_KEY,1)
#define SDF_GenerateKeyWithECC COMMAND(TYPE_KEY,1)
#define SDF_GenerateAgreementDataWithECC COMMAND(TYPE_KEY,1)
#define SDF_GenerateAgreementDataAndKeyWithECC COMMAND(TYPE_KEY,1)
#define IMPORT_KEY_ISK_RSA  COMMAND(TYPE_KEY,1)
#define IMPORT_KEY_ISK_ECC  COMMAND(TYPE_KEY,1)
#define IMPORT_KEY_KEK  COMMAND(TYPE_KEY,1)
#define IMPORT_KEY  COMMAND(TYPE_KEY,1)
#define DESTROY_KEY  COMMAND(TYPE_KEY,1)
#define SDF_ExchangeDigitEnvelopeBaseOnRSA  COMMAND(TYPE_KEY,1)
#define SDF_ExchangeDigitEnvelopeBaseOnECC  COMMAND(TYPE_KEY,1)

/*#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)
#define   COMMAND(TYPE_KEY,1)*/
#endif
