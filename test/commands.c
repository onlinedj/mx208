#include "../include/commands.h"

#include <stdio.h>

int main(int argc, const char *argv[])
{
    printf("GET_DEVICE_INFO type=%d,id=%d\n",GET_TYPE(GET_DEVICE_INFO),GET_ID(GET_DEVICE_INFO));
    printf("EXPORT_SIGN_PUB_KEY_RSA type=%d,id=%d\n",GET_TYPE(EXPORT_SIGN_PUB_KEY_RSA),GET_ID(EXPORT_SIGN_PUB_KEY_RSA));
    
    return 0;
}
