#include "command_handler.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


static QUEUE *queues[QUEUES_SIZE];

void init_queues()
{
    int i = 0;
    for(i = 0;i < 4; i++) {
        QUEUE *q = (QUEUE *) malloc(sizeof(QUEUE));
        bzero(q,sizeof(QUEUE));    
        init_queue(q);
        queues[i] = q;
    }

}

void start_command_threads()
{
    long i = 0;
    for(i = 0;i < 1; i++) {
        pthread_t tid;
        pthread_create(&tid,NULL,handle_command, (void *) i);
        printf("start_command_threads ok!\n");
    }
    
}

void destroy_queues()
{
   //TODO free the malloc mems. 
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
    long i;
    i = (long)arg;
    while(1)
    {
        uint32_t *header;
        if(dequeue(queues[i], (void**)&header))
        {
            uint32_t my[4] = {5,sizeof(DEVICEINFO)+sizeof(uint32_t),1,0};
            int result = send(*(header+4),my,sizeof(uint32_t)*4,0);
            uint32_t data_size = sizeof(DEVICEINFO);
            result = send(*(header+4),&data_size,sizeof(uint32_t),0);
            DEVICEINFO info;
            strncpy(info.IssuerName,"mx tech",8);
            strncpy(info.DeviceName,"mx 208",7);
            strncpy(info.DeviceSerial,"123456789",10);
            info.DeviceVersion=1;
            info.StandardVersion=2;
            info.AsymAlgAbility[0] = 3;
            info.AsymAlgAbility[1] = 4;
            info.SymAlgAbility = 5;
            info.HashAlgAbility = 6;
            info.BufferSize = 1024;

            result = send(*(header+4),info,sizeof(DEVICEINFO),0);
            printf("handle_command result=%d\n",result);
        } 
        free(header);
    }
}
