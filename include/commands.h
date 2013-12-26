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
#include <stdint.h>

#define TYPE_DEVICE 0x00000000
#define TYPE_KEY 0x00000001
#define TYPE_ALGORITHM 0x00000002
#define TYPE_FILE 0x00000003
/*#define COMMAND(type,id) (type<<24|id)
#define GET_ID(command) (command &0x00FFFFFF)*/

//device
#define FUNID_SDF_OPENDEVICE 0x00000001
#define FUNID_SDF_CLOSEDEVICE 0x00000002
#define FUNID_SDF_OPENSESSION 0x00000003
#define FUNID_SDF_CLOSESESSION 0x00000004
#define FUNID_SDF_GETDEVICEINFO 0x00000005
//key
#define FUNID_SDF_GETPRIVATEKEYACCESSRIGHT 0x00000007
#define FUNID_SDF_RELEASEPRIVATEKEYACCESSRIGHT 0x00000008
#define FUNID_SDF_EXPORTSIGNPUBLICKEY_RSA 0x00000009
#define FUNID_SDF_EXPORTENCPUBLICKEY_RSA 0x00000010
#define FUNID_SDF_EXPORTSIGNPUBLICKEY_ECC 0x00000016
#define FUNID_SDF_EXPORTENCPUBLICKEY_ECC 0x00000017
#define FUNID_SDF_IMPORTKEY 0x00000028
#define FUNID_SDF_DESTORYKEY 0x00000029
//algorithm
#define FUNID_SDF_GENERATERANDOM 0x00000006
#define FUNID_SDF_GENERATEKEYPAIR_RSA 0x00000011
#define FUNID_SDF_GENERATEKEYWITHIPK_RSA 0x00000012
#define FUNID_SDF_GENERATEKEYWITHEPK_RSA 0x00000013
#define FUNID_SDF_IMPORTKEYWITHISK_RSA 0x00000014
#define FUNID_SDF_EXCHANGEDIGITENVELOPEBASEONRSA 0x00000015
#define FUNID_SDF_GENERATEKEYPAIR_ECC 0x00000018
#define FUNID_SDF_GENERATEKEYWITHIPK_ECC 0x00000019
#define FUNID_SDF_GENERATEKEYWITHEPK_ECC 0x00000020
#define FUNID_SDF_IMPORTKEYWITHISK_ECC 0x00000021
#define FUNID_SDF_GENERATEAGREEMENTDATAWITHECC 0x00000022
#define FUNID_SDF_GENERATEKEYWITHECC 0x00000023
#define FUNID_SDF_GENERATEAGREEMENTDATAANDKEYWITHECC 0x00000024
#define FUNID_SDF_EXCHANGEDIGITENVELOPEBASEONECC 0x00000025
#define FUNID_SDF_GENERATEKEYWITHKEK 0x00000026
#define FUNID_SDF_IMPORTKEYWITHKEK 0x00000027
#define FUNID_SDF_EXTERNALPUBLICKEYOPERATION_RSA 0x00000030
#define FUNID_SDF_EXTERNALPRIVATEKEYOPERATION_RSA 0x00000031
#define FUNID_SDF_INTERNALPUBLICKEYOPERATION_RSA 0x00000032
#define FUNID_SDF_INTERNALPRIVATEKEYOPERATION_RSA 0x00000033
#define FUNID_SDF_EXTERNALSIGN_ECC 0x00000034
#define FUNID_SDF_EXTERNALVERIFY_ECC 0x00000035
#define FUNID_SDF_INTERNALSIGN_ECC 0x00000036
#define FUNID_SDF_INTERNALVERIFY_ECC 0x00000037
#define FUNID_SDF_EXTERNALENCRYTP_ECC 0x00000038
#define FUNID_SDF_EXTERNALDECRYPT_ECC 0x00000039
#define FUNID_SDF_ENCRYPT 0x00000040
#define FUNID_SDF_DECRYPT 0x00000041
#define FUNID_SDF_CALCULATEMAC 0x00000042
#define FUNID_SDF_HASHINIT 0x00000043
#define FUNID_SDF_HASHUPDATE 0x00000044
#define FUNID_SDF_HASHFINAL 0x00000045
//file
#define FUNID_SDF_CREATEFILE 0x00000046
#define FUNID_SDF_READFILE 0x00000047
#define FUNID_SDF_WRITEFILE 0x00000048
#define FUNID_SDF_DELETEFIL 0x00000049

int GET_TYPE(uint32_t command)
{

    switch(command){ 
    case FUNID_SDF_OPENDEVICE :
    case FUNID_SDF_CLOSEDEVICE :
    case FUNID_SDF_OPENSESSION :
    case FUNID_SDF_CLOSESESSION :
    case FUNID_SDF_GETDEVICEINFO :
        return 0;
    case FUNID_SDF_GETPRIVATEKEYACCESSRIGHT :
    case FUNID_SDF_RELEASEPRIVATEKEYACCESSRIGHT :
    case FUNID_SDF_EXPORTSIGNPUBLICKEY_RSA :
    case FUNID_SDF_EXPORTENCPUBLICKEY_RSA :
    case FUNID_SDF_EXPORTSIGNPUBLICKEY_ECC :
    case FUNID_SDF_EXPORTENCPUBLICKEY_ECC :
    case FUNID_SDF_IMPORTKEY :
    case FUNID_SDF_DESTORYKEY :
        return 1;
    case FUNID_SDF_CREATEFILE :
    case FUNID_SDF_READFILE :
    case FUNID_SDF_WRITEFILE :
    case FUNID_SDF_DELETEFILE :
        return 3;
    default:
        return 2;
  } 
}
#endif
