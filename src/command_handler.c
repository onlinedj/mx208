#include "command_handler.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define THREAD_COUNT 4

static QUEUE *queues[QUEUES_SIZE];

void init_queues()
{
    int i = 0;
    for(i = 0;i < THREAD_COUNT; i++) 
    {
        init_queue(&queues[i]);
    }

}


void destroy_queues()
{
    int i = 0;
    for(i = 0; i < THREAD_COUNT; i++) 
    {
        destroy_queue(queues[i]);
    }
}

QUEUE* get_queue(int type)
{
    return queues[type];
}

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

void* handle_command(void *arg)
{
    uint32_t i;
    i = (uint32_t)arg;
    uint8_t buffer[BUFFER_MAX];
    uint8_t output[BUFFER_MAX];
    memset(buffer,0,BUFFER_SIZE);
    while(1)
    {
        if(dequeue(queues[i], buffer))
        {
            uint32_t *tmp = (uint32_t *)buffer;
            printf("in command_handler buffer=%d,%d,%d,%d,%d\n",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4]);
            switch(tmp[0])
            {
                case 1:
                    {
                        /*printf("prepare info for result\n");*/
                        uint32_t my[4] = {(uint32_t)*(tmp+4),sizeof(DEVICEINFO)+sizeof(uint32_t),1,0};
                        memcpy(output,my,sizeof(uint32_t)*4);
                        uint32_t data_size = sizeof(DEVICEINFO);
                        memcpy(output+sizeof(uint32_t)*4,&data_size,sizeof(uint32_t));

                        DEVICEINFO info;
                        memcpy(info.IssuerName,"mx tech",8);
                        memcpy(info.DeviceName,"mx 208",7);
                        memcpy(info.DeviceSerial,"123456789",10);
                        info.DeviceVersion=1;
                        info.StandardVersion=2;
                        info.AsymAlgAbility[0] = 3;
                        info.AsymAlgAbility[1] = 4;
                        info.SymAlgAbility = 5;
                        info.HashAlgAbility = 6;
                        info.BufferSize = 1024;
                        memcpy(output+sizeof(uint32_t)*5,&info,sizeof(info));
                        int total = sizeof(uint32_t)*5+sizeof(DEVICEINFO);

                        int result = send(*(tmp+4),output,total,0);
                        printf("handle_command sockfd=%u, result=%d,total=%d\n",*(tmp+4),result,total);

                        break;
                    }
                default:

                    break;
            } 
            memset(buffer,0,BUFFER_MAX);
        } 
        else 
        {
            queue_wait(queues[i]);
        }
    }
}
