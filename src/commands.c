#include "commands.h"


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
