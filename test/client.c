#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <pthread.h>
#include <string.h>

#include "mx_std.h"
#include "commands.h"

void *send_info(void *arg)
{
    return NULL;
}

int main(int argc, char *argv[])
{
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 
    int counter = 0;

    if(argc != 4)
    {
        printf("\n Usage: %s <ip of server> \n",argv[0]);
        return 1;
    } 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint32_t)atoi(argv[2])); 

    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } else {
        /*int i;
        for(i=0;i<5;i++)
        {
            pthread_t tid;
            pthread_create(&tid,NULL,send_info,NULL);
        }*/
        uint8_t buffer[65536];
        memset(buffer,0,65536);
        switch (atoi(argv[3]))
        {
            case 0:
                {
                    uint32_t info[4] = {0x00000001,0,0,0};
                    int result = send(sockfd, info, sizeof(uint32_t)*4,0); 
                    printf("%d send result=%d,errno=%d\n",sockfd,result,errno);
                    memset(buffer,0,65536);
                    while(1)
                    {
                        uint32_t *tmp = (uint32_t *)buffer;
                        int n = recv(sockfd,buffer,65536,0); 
                        struct DeviceInfo_st info;
                        memcpy(&info,buffer+4*5,sizeof(info));
                        printf("recv success!recev=%d;header:%u,%u,%u,%u;\n",n,tmp[0],tmp[1],tmp[2],tmp[3]);
                        printf("recv success!info=%s,%s,%s,%u,%u,%u,%u,%u,%u,%u\n",info.IssuerName,info.DeviceName,info.DeviceSerial,
                          info.DeviceVersion,info.StandardVersion,info.AsymAlgAbility[0],info.AsymAlgAbility[1],info.SymAlgAbility,info.HashAlgAbility,info.BufferSize);
                        break;
                    }
                    memset(buffer,0,65536);
                
                }
                break;
            case 1:
                {
                    unsigned char ins[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
                    unsigned char keys[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
                    int a;
                    for(a =0; a<16;a++)
                    {
                        printf("%2X",ins[a]);
                    }
                    printf("\n");
                    for(a =0; a<16;a++)
                    {
                        printf("%2X",keys[a]);
                    }
                    printf("\n");

                    memset(buffer,0,65536);
                    uint32_t info[4] = {SDF_ENCRYPT,68,2,0};
                    memcpy(buffer,info,16);
                    int key=110,key_s = 4;
                    memcpy(buffer+16,&key_s,4);
                    memcpy(buffer+20,&key,4);
                    int algid=119,algid_s = 4;
                    memcpy(buffer+24,&algid_s,4);
                    memcpy(buffer+28,&algid,4);
                    int puciv=114,puc_s = 4;
                    memcpy(buffer+32,&puc_s,4);
                    memcpy(buffer+36,&puciv,4);
                    int in_size = 16;
                    memcpy(buffer+40,&in_size,4);
                    memcpy(buffer+44,ins,16);
                    memcpy(buffer+60,&key_s,4);
                    memcpy(buffer+64,&in_size,4);
                    int result = send(sockfd, buffer, 68,0); 
                    printf("%d send result=%d,errno=%d buffer size:%d,%d\n%s\n",sockfd,result,errno,*(buffer+16),*(buffer+36),buffer);
                    memset(buffer,0,65536);
                    while(1)
                    {
                        int n = recv(sockfd,buffer,65536,0); 
                        uint32_t *tmp = (uint32_t *)buffer;
                        printf("recv success!recev=%d;header:%u,%u,%u,%u;\n",n,tmp[0],tmp[1],tmp[2],tmp[3]);
                        int out_size = *(tmp+4);
                        printf("outsize=%d\n",out_size);
                        int i ;
                        for(i =20; i<20+16;i++)
                        {
                            printf("%2X",buffer[i]);
                        }
                        printf("\n");

                        break;
                    }
                    memset(buffer,0,65536);

                }
                break;
            case 2:
                {
                    unsigned char ins[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
                    unsigned char keys[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
                    int a;
                    for(a =0; a<16;a++)
                    {
                        printf("%2X",ins[a]);
                    }
                    printf("\n");
                    for(a =0; a<16;a++)
                    {
                        printf("%2X",keys[a]);
                    }
                    printf("\n");

                    memset(buffer,0,65536);
                    uint32_t info[4] = {SDF_DECRYPT,68,2,0};
                    memcpy(buffer,info,16);
                    int key=110,key_s = 4;
                    memcpy(buffer+16,&key_s,4);
                    memcpy(buffer+20,&key,4);
                    int algid=119,algid_s = 4;
                    memcpy(buffer+24,&algid_s,4);
                    memcpy(buffer+28,&algid,4);
                    int puciv=114,puc_s = 4;
                    memcpy(buffer+32,&puc_s,4);
                    memcpy(buffer+36,&puciv,4);
                    int in_size = 16;
                    memcpy(buffer+40,&in_size,4);
                    memcpy(buffer+44,ins,16);
                    memcpy(buffer+60,&key_s,4);
                    memcpy(buffer+64,&in_size,4);
                    int result = send(sockfd, buffer, 68,0); 
                    printf("%d send result=%d,errno=%d buffer size:%d,%d\n",sockfd,result,errno,*(buffer+16),*(buffer+36));
                    memset(buffer,0,65536);
                    while(1)
                    {
                        int n = recv(sockfd,buffer,65536,0); 
                        uint32_t *tmp = (uint32_t *)buffer;
                        printf("recv success!recev=%d;header:%u,%u,%u,%u;\n",n,tmp[0],tmp[1],tmp[2],tmp[3]);
                        int out_size = *(tmp+4);
                        printf("outsize=%d\n",out_size);
                        int i ;
                        for(i =20; i<20+16;i++)
                        {
                            printf("%2X",buffer[i]);
                        }
                        printf("\n");

                        break;
                    }
                    memset(buffer,0,65536);
                }
                break;
            default:
                break;
        }
    }

    return 0;
}

