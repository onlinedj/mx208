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
    for(i = 0;i < 4; i++) {
        pthread_t tid;
        pthread_create(&tid,NULL,handle_command, (void *) i);
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

void* handle_command(void *arg)
{
    long i;
    i = (long)arg;
    while(1)
    {
        uint32_t *header;
        if(dequeue(queues[i], (void**)&header))
        {
            uint32_t my[4] = {1,222,333,444};
            int result = send(*(header+4),my,sizeof(uint32_t)*4,0);
            printf("handle_command result=%d\n",result);
        } 
        else 
        {
            sleep(2);
        }
    }
}
