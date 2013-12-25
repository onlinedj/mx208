#include "commands.h"
#include "mx_std.h"

#include <stdio.h>
#include <string.h>

int main(int argc, const char *argv[])
{
    printf("GET_DEVICE_INFO type=%d,id=%d\n",GET_TYPE(GET_DEVICE_INFO),GET_ID(GET_DEVICE_INFO));
    printf("EXPORT_SIGN_PUB_KEY_RSA type=%d,id=%d\n",GET_TYPE(EXPORT_SIGN_PUB_KEY_RSA),GET_ID(EXPORT_SIGN_PUB_KEY_RSA));
    
    ECCrefPublicKey key;
    key.bits=4;
    uint8_t x[32] = {1,1,1,1};
    memcpy(key.x,x,32);
    ECCrefPublicKey key2;
    key2.bits=8;
    uint8_t x2[32] = {3,3,3,3};
    memcpy(key2.x,x2,32);
    ECCrefPublicKey *key_p;
    ECCrefPublicKey *key_p2;
    key_p = &key;
    key_p2 = &key2;
    *key_p2 = *key_p;
    printf("key_p2:%d\n",key_p2->bits);
    int i;
    for(i=0;i<32;i++)
    {
        printf("%02x",key_p2->x[i]); 
    }
    printf("\n");
    return 0;
}
