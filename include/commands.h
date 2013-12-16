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
#define TYPE_DEVICE 0x00000000
#define TYPE_KEY 0x00000001
#define TYPE_ALGORITHM 0x00000002
#define TYPE_FILE 0x00000003
#define COMMAND(type,id) (type<<24|id)
#define GET_TYPE(command) (command>>24&0x000000FF)
#define GET_ID(command) (command &0x00FFFFFF)
//device type command
#define GET_DEVICE_INFO COMMAND(TYPE_DEVICE,1)
//key type command
#define GET_KEY_ACCESS  COMMAND(TYPE_KEY,1)
#define RELEASE_KEY_ACCESS  COMMAND(TYPE_KEY,2)
#define EXPORT_SIGN_PUB_KEY_RSA COMMAND(TYPE_KEY,3)
#define EXPORT_ENC_PUB_KEY_RSA  COMMAND(TYPE_KEY,4)
#define EXPORT_SIGN_PUB_KEY_ECC COMMAND(TYPE_KEY,5)
#define EXPORT_ENC_PUB_KEY_ECC  COMMAND(TYPE_KEY,6)
#define GENERATE_KEYPAIR_RSA  COMMAND(TYPE_KEY,7)
#define GENERATE_KEY_IPK_RSA  COMMAND(TYPE_KEY,8)
#define GENERATE_KEY_EPK_RSA  COMMAND(TYPE_KEY,9)
#define GENERATE_KEYPAIR_ECC  COMMAND(TYPE_KEY,10)
#define GENERATE_KEY_IPK_ECC  COMMAND(TYPE_KEY,11)
#define GENERATE_KEY_EPK_ECC  COMMAND(TYPE_KEY,12)
#define GENERATE_KEY_KEK COMMAND(TYPE_KEY,13)
#define GENERATE_KEY_ECC COMMAND(TYPE_KEY,14)
#define GENERATE_AGREEMENT_DATA_ECC COMMAND(TYPE_KEY,15)
#define GENERATE_AGREEMENT_DATA_KEY_ECC COMMAND(TYPE_KEY,16)
#define IMPORT_KEY_ISK_RSA  COMMAND(TYPE_KEY,17)
#define IMPORT_KEY_ISK_ECC  COMMAND(TYPE_KEY,18)
#define IMPORT_KEY_KEK  COMMAND(TYPE_KEY,19)
#define IMPORT_SESSION_KEY  COMMAND(TYPE_KEY,20)
#define DESTROY_SESSION_KEY  COMMAND(TYPE_KEY,21)
#define EXCHANGE_DIGIT_ENVELOPE_RSA  COMMAND(TYPE_KEY,22)
#define EXCHANGE_DIGIT_ENVELOPE_ECC  COMMAND(TYPE_KEY,23)
//algorithm type command
#define SDF_ENCRYPT  COMMAND(TYPE_ALGORITHM,1)
#define SDF_DECRYPT  COMMAND(TYPE_ALGORITHM,2)
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
