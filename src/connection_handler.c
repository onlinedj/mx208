#include "connection_handler.h"

#include <stdint.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "command_handler.h"


void *handle_connection(void* arg)
{
    uint32_t connfd;
    connfd = (uint32_t)arg;
    if(DEBUG_CONN) printf("current thread %lu , connfd=%u\n", (unsigned long)pthread_self(), connfd);
    uint8_t buffer[BUFFER_MAX*sizeof(uint8_t)] ;
    while(1)
    {
        
        int n = recv(connfd, buffer, BUFFER_SIZE, 0);
        if(n>0)
        {
            uint32_t *tmp = (uint32_t *) buffer;
            if(DEBUG_CONN) printf("connection_handler n=%d, header :%d,%d,%d,%d,%d,%d\n",n, *tmp,*(tmp+1),*(tmp+2),*(tmp+3),*(tmp+4),*(tmp+5));
            int command = tmp[0];
            int type = GET_TYPE(command);
            switch(type)
            {
                case TYPE_DEVICE:
                case TYPE_KEY:
                case TYPE_ALGORITHM:
                case TYPE_FILE:
                    if(DEBUG_CONN) printf("enqueue type=%d\n",GET_TYPE(command));
                    if(enqueue(get_queue(type), buffer, connfd))
                    {
                        queue_notify(get_queue(GET_TYPE(command)));
                    }
                    break;
                default:
                   if(DEBUG_CONN) printf("do nothing just break.");
                    break;
            }
            memset(buffer,0,BUFFER_MAX);
        }
    }

}
