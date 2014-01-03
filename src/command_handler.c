#include "command_handler.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "key_manager.h"
#include "device_manager.h"
#include "file_manager.h"
#include "algorithm.h"


static QUEUE *queues[THREAD_COUNT];

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

int process_command(int type, uint8_t *params, uint8_t *result)
{
    int total = 0;
    switch(type)
    {
    case TYPE_DEVICE:
        total = process_command_device(params, result);
        break;
    case TYPE_KEY:
        total = process_command_key(params, result);
        break;
    case TYPE_ALGORITHM:
        //total = process_command_algorithm(params,result);
        break;
    case TYPE_FILE:
        total = process_command_file(params, result);
        break;
    default:
        break;
    }
    return total;
}

void* handle_command(void *arg)
{
    uint32_t type;
    type = (uint32_t)(uint64_t)arg;
    uint8_t buffer[BUFFER_MAX];
    uint8_t output[BUFFER_MAX];
    memset(buffer,0,BUFFER_SIZE);
    while(1)
    {
        if(dequeue(queues[type], buffer))
        {
            uint32_t *tmp = (uint32_t *)buffer;
            if(DEBUG_COMM) printf("in command_handler %d buffer=%d,%d,%d,%d,%d,%d,%d\n",type,tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5],tmp[6]);
            int total = 0;
            if((total = process_command(type, buffer, output)) > 0)
            {
                int result = send(*(tmp+4),output,total,0);
                if(DEBUG_COMM) printf("handle_command sockfd=%u, result=%d,total=%d\n",*(tmp+4),result,total);
            }

            memset(buffer,0,BUFFER_MAX);
            memset(output,0,BUFFER_MAX);
        } 
        else 
        {
            queue_wait(queues[type]);
        }
    }
}
